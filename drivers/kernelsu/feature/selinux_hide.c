#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "security.h"
#include "policy/feature.h"
#include "ksu.h"
#include "uapi/feature.h"
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"
#include "compat/kernel_compat.h"

#ifndef __nocfi
#define __nocfi
#endif

#ifdef KSU_COMPAT_USE_SELINUX_STATE
extern struct selinux_state selinux_state;
#define KSU_HAS_SELINUX_STATE 1
#else
#define KSU_HAS_SELINUX_STATE 0
#endif

static bool ksu_selinux_hide_enabled __read_mostly = true;

static int ksu_patch_fops_slot(void **slot, void *new_fn)
{
    unsigned long addr   = (unsigned long)slot;
    unsigned long base   = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    struct page *page    = phys_to_page(__pa(base));
    void *w;

    if (!page)
        return -EFAULT;

    w = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!w)
        return -ENOMEM;

    WRITE_ONCE(*(void **)((unsigned long)w + offset), new_fn);
    smp_mb();
    vunmap(w);
    return 0;
}

static struct file_operations *ksu_resolve_fops(const char *path_str)
{
    struct path path;
    struct file_operations *fops = NULL;

    if (kern_path(path_str, LOOKUP_FOLLOW, &path))
        return NULL;
    if (path.dentry && d_inode(path.dentry))
        fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
    path_put(&path);
    return fops;
}

static struct page *ksu_fake_status_page __read_mostly = NULL;
static int (*orig_status_open)(struct inode *, struct file *) = NULL;
static struct file_operations *g_status_fops;

static struct page *ksu_get_real_status_page(void)
{
#if KSU_HAS_SELINUX_STATE
    return selinux_kernel_status_page(&selinux_state);
#else
    return selinux_kernel_status_page();
#endif
}

static int ksu_prepare_fake_status_page(void)
{
    struct page *real, *fake;
    struct selinux_kernel_status *rs, *fs;

    if (READ_ONCE(ksu_fake_status_page))
        return 0;

    real = ksu_get_real_status_page();
    if (!real)
        return -ENOENT;

    fake = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!fake)
        return -ENOMEM;

    rs = page_address(real);
    fs = page_address(fake);
    memcpy(fs, rs, sizeof(*fs));

    fs->enforcing = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    fs->sequence    = 4;
    fs->policyload  = 1;
#else
    fs->sequence    = 0;
    fs->policyload  = 0;
#endif

    smp_store_release(&ksu_fake_status_page, fake);
    pr_info_ratelimited("selinux_hide: fake status ready seq=%d\n", fs->sequence);
    return 0;
}

static __nocfi int ksu_status_open(struct inode *inode, struct file *filp)
{
    if (likely(ksu_selinux_hide_enabled && current_uid().val >= 10000)) {
        struct page *fp = smp_load_acquire(&ksu_fake_status_page);
        if (fp) {
            filp->private_data = fp;
            return 0;
        }
    }
    return orig_status_open(inode, filp);
}

static void ksu_hook_status_open(void)
{
    struct file_operations *fops;
    int ret;

    if (orig_status_open)
        return;

    fops = ksu_resolve_fops("/sys/fs/selinux/status");
    if (!fops || !fops->open)
        return;

    g_status_fops = fops;
    orig_status_open = fops->open;
    ret = ksu_patch_fops_slot((void **)&fops->open, ksu_status_open);
    if (ret)
        pr_warn("selinux_hide: patch status open failed: %d\n", ret);
}

static int selinux_hide_get(u64 *v)
{
    *v = ksu_selinux_hide_enabled ? 1 : 0;
    return 0;
}

static int selinux_hide_set(u64 v)
{
    ksu_selinux_hide_enabled = !!v;
    ksu_set_selinux_hide_enabled(ksu_selinux_hide_enabled);
    pr_info_ratelimited("selinux_hide: enabled=%d\n", ksu_selinux_hide_enabled);
    return 0;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_get,
    .set_handler = selinux_hide_set,
};

static int ksu_selinux_hide_init_thread(void *data)
{
    int tries = 0;

    set_user_nice(current, 19);

try_again:
    if (ksu_prepare_fake_status_page()) {
        if (++tries > 10)
            return 0;
        msleep(1000);
        goto try_again;
    }
    ksu_hook_status_open();
    return 0;
}

void ksu_selinux_hide_handle_second_stage(void)
{
    if (!READ_ONCE(ksu_fake_status_page))
        ksu_prepare_fake_status_page();
    ksu_hook_status_open();
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
    if (!READ_ONCE(ksu_fake_status_page))
        ksu_prepare_fake_status_page();
    ksu_hook_status_open();
}

void __init ksu_selinux_hide_init(void)
{
    ksu_set_selinux_hide_enabled(ksu_selinux_hide_enabled);
    if (ksu_register_feature_handler(&selinux_hide_handler))
        pr_err("selinux_hide: register feature failed\n");

    kthread_run(ksu_selinux_hide_init_thread, NULL, "ksu_selinux_hide");
}

void __exit ksu_selinux_hide_exit(void)
{
    ksu_set_selinux_hide_enabled(false);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);

    if (g_status_fops && orig_status_open)
        ksu_patch_fops_slot((void **)&g_status_fops->open, orig_status_open);
}

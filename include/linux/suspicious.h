#ifndef _LINUX_SUSPICIOUS_H_
#define _LINUX_SUSPICIOUS_H_

#include <linux/fs.h>
#include <linux/mount.h>

int is_suspicious_path(const struct path* const file);
int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root);
int suspicious_path(const struct filename* const name);
int is_suspicious_user_path(const char __user *pathname);
#endif

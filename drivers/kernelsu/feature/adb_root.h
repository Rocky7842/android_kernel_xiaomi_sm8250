#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <linux/jump_label.h>
#include <asm/ptrace.h>

struct filename;
struct user_arg_ptr;

DECLARE_STATIC_KEY_FALSE(ksu_adb_root);

long ksu_adb_root_handle_execve(struct pt_regs *regs);
long ksu_adb_root_handle_execveat(struct pt_regs *regs);
long ksu_adb_root_handle_execve_manual(struct filename *filename,
				       struct user_arg_ptr *envp);

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif
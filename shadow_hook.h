#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>

/* ARM64 调试钩子返回值规范 */
#define DBG_HOOK_HANDLED 0
#define DBG_HOOK_ERROR   1

/* 对应内核空间的业务请求结构体 (用于下发 il2cpp 偏移等) */
struct shadow_request {
    pid_t pid;
    unsigned long vaddr;
    unsigned long target_vaddr;
    u32 custom_rot[3];
    int is_rot_hook;
};

/* 用于接收从 loader.sh 动态下发的内核符号绝对地址 */
struct shadow_sym_request {
    unsigned long p_register_user_step_hook;
    unsigned long p_unregister_user_step_hook;
    unsigned long p_user_enable_single_step;
    unsigned long p_user_disable_single_step;
    unsigned long p_fpsimd_preserve_current_state;
    unsigned long p_fpsimd_update_current_state;
    unsigned long p_register_user_break_hook;
    unsigned long p_unregister_user_break_hook;
};

/* 核心导出函数声明 */
extern int shadow_fault_init_dynamic(struct shadow_sym_request *syms);
extern void shadow_fault_exit(void);
extern int add_shadow(struct shadow_request *req);
extern int update_shadow_rot(struct shadow_request *req);
extern int del_shadow(struct shadow_request *req);

#endif /* _SHADOW_HOOK_H */

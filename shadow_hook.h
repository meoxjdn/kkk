#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>

#define DBG_HOOK_HANDLED 0
#define DBG_HOOK_ERROR   1

/* 驱动通信协议 IOCTL 魔法字 */
#define WUWA_IOCTL_ADD_SHADOW _IOW('W', 1, struct shadow_request)
#define WUWA_IOCTL_RAW_PATCH  _IOW('W', 2, struct raw_patch_req)
#define WUWA_IOCTL_CLEAN_ALL  _IO('W', 3)  /* 核爆级内存清理指令 */

/* BRK 硬件断点劫持请求包 */
struct shadow_request {
    pid_t pid;
    unsigned long vaddr;
    unsigned long target_vaddr;
    u32 custom_rot[3];
    int is_rot_hook;
    unsigned long jump_vaddr; /* 极客流无痕跳转目标地址 */
};

/* 强力穿透写入请求包 */
struct raw_patch_req {
    pid_t pid;
    uint64_t addr;
    uint32_t data;
};

/* 动态基址投喂请求包 */
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

extern int shadow_fault_init_dynamic(struct shadow_sym_request *syms);
extern void shadow_fault_exit(void);
extern int add_shadow(struct shadow_request *req);
extern int update_shadow_rot(struct shadow_request *req);
extern int del_shadow(struct shadow_request *req);
extern void clear_all_shadows(void); /* 新增内存清空接口 */

#endif /* _SHADOW_HOOK_H */

/*
 * =====================================================================================
 *       Filename:  shadow_hook.h
 *    Description:  Ghost Core V10.13 Protocol Definitions (Hybrid CFG Router)
 * =====================================================================================
 */
#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHOST_MAGIC 'G'

#define IOCTL_CMD_GET_PID    _IOWR(GHOST_MAGIC, 1, struct get_pid_req)
#define IOCTL_CMD_GET_BASE   _IOWR(GHOST_MAGIC, 2, struct module_base_req)
#define IOCTL_SET_HWBP       _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_PAUSE_HWBP     _IOW(GHOST_MAGIC, 4, struct hwbp_req)
#define IOCTL_RESUME_HWBP    _IOW(GHOST_MAGIC, 5, struct hwbp_req)

struct get_pid_req {
    char process_name[64];
    pid_t pid;
};

struct module_base_req {
    pid_t pid;
    char mod_name[64];
    uint64_t base_addr;
};

struct hwbp_req {
    pid_t tgid;
    uint64_t target_addr;
    int function_id;
    uint64_t aux_addr;      /* 辅助地址：用于传递 OFF_PAUSE_JMP 等需要跳转的动态目标 */
};

extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern long handle_get_pid(struct get_pid_req *req);
extern long handle_get_module_base(struct module_base_req *req);
extern long handle_hwbp_ioctl(unsigned int cmd, unsigned long arg);

#endif /* _SHADOW_HOOK_H */

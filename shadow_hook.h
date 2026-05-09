/*
 * =====================================================================================
 *       Filename:  shadow_hook.h
 *    Description:  Ghost Core V10.11 Protocol Definitions (HWBP State-Machine Gateway)
 * =====================================================================================
 */
#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHOST_MAGIC 'G'

/* 
 * 极客网关指令集：基于控制流劫持的 HWBP 协议栈
 * 注意：序列号重新分配为 1~5，用户态工具需严格对齐
 */
#define IOCTL_CMD_GET_PID    _IOWR(GHOST_MAGIC, 1, struct get_pid_req)
#define IOCTL_CMD_GET_BASE   _IOWR(GHOST_MAGIC, 2, struct module_base_req)

/* HWBP 生命期与状态机协作指令 (已修复为 _IOW，防止 copy_from_user 野指针异常) */
#define IOCTL_SET_HWBP       _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_PAUSE_HWBP     _IOW(GHOST_MAGIC, 4, struct hwbp_req)
#define IOCTL_RESUME_HWBP    _IOW(GHOST_MAGIC, 5, struct hwbp_req)

/* Ring 0 内核级目标进程索敌请求 */
struct get_pid_req {
    char process_name[64];
    pid_t pid;
};

/* Ring 0 内核级基址获取请求 */
struct module_base_req {
    pid_t pid;
    char mod_name[64];
    uint64_t base_addr;
};

/* 硬件断点分发与路由请求 */
struct hwbp_req {
    pid_t tgid;             /* 目标进程组 ID */
    uint64_t target_addr;   /* 需要下发硬件执行断点的绝对地址 */
    int function_id;        /* 状态机路由键值 (1~4: 基础覆盖, 5: 零开销状态机) */
};

extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern long handle_get_pid(struct get_pid_req *req);
extern long handle_get_module_base(struct module_base_req *req);
extern long handle_hwbp_ioctl(unsigned int cmd, unsigned long arg);

#endif /* _SHADOW_HOOK_H */

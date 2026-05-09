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
 * 极客网关指令集：完全重构为基于控制流劫持的 HWBP 协议栈
 */
#define IOCTL_CMD_GET_PID    _IOWR(GHOST_MAGIC, 1, struct get_pid_req)
#define IOCTL_CMD_GET_BASE   _IOWR(GHOST_MAGIC, 2, struct module_base_req)

/* V10.11 专属：HWBP 生命期与状态机跳板协作指令 */
#define IOCTL_SET_HWBP       _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_PAUSE_HWBP     _IO(GHOST_MAGIC, 4)  /* 安全屋关闸 (无参) */
#define IOCTL_RESUME_HWBP    _IO(GHOST_MAGIC, 5)  /* 安全屋开闸 (无参) */

/* Ring 0 内核级目标进程索敌请求 (基于 Cmdline 解析) */
struct get_pid_req {
    char process_name[64];  /* 由用户态传入的包名/进程名 */
    pid_t pid;              /* 内核解析后填充的 PID */
};

/* Ring 0 内核级基址获取请求 (基于锁降级 VMA 遍历) */
struct module_base_req {
    pid_t pid;
    char mod_name[64];      /* 目标模块名，如 libil2cpp.so */
    uint64_t base_addr;     /* 提取到的绝对物理基址 */
};

/* 硬件断点分发与路由请求 */
struct hwbp_req {
    pid_t tgid;             /* 目标进程组 ID */
    uint64_t target_addr;   /* 需要下发硬件执行断点的绝对地址 */
    int function_id;        /* 状态机路由键值 (对应内核 handler 里的 switch_case) */
};

/* ==========================================================
 * 核心引擎暴漏给网关的链接符号 (联动 core_hook.c)
 * ========================================================== */
extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern long handle_get_pid(struct get_pid_req *req);
extern long handle_get_module_base(struct module_base_req *req);
extern long handle_hwbp_ioctl(unsigned int cmd, unsigned long arg);

#endif /* _SHADOW_HOOK_H */

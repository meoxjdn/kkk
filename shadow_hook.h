#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define DBG_HOOK_HANDLED 0
#define DBG_HOOK_ERROR   1

/* 
 * 驱动通信协议 IOCTL 魔法字 (升级为 V10 标准) 
 * 彻底废除 RAW_PATCH，全面转向物理维度控制
 */
#define GHOST_MAGIC 'G'

#define IOCTL_CMD_ALLOC_GHOST   _IOWR(GHOST_MAGIC, 1, struct ghost_alloc_req)
#define IOCTL_CMD_SET_UXN_TRAP  _IOW(GHOST_MAGIC, 2, struct uxn_trap_req)
#define IOCTL_CMD_SET_HWBP      _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_CMD_DISABLE_HWBP  _IOW(GHOST_MAGIC, 4, struct hwbp_req)
#define IOCTL_CMD_ENABLE_HWBP   _IOW(GHOST_MAGIC, 5, struct hwbp_req)
#define IOCTL_CMD_HIDE_VMA      _IOW(GHOST_MAGIC, 6, struct hide_vma_req)

/* 幽灵内存分配请求 */
struct ghost_alloc_req {
    unsigned long target_va;    
    unsigned long size;         
    void __user *bytecode;      /* DBI 重编译后的纯净机器码 */
};

/* UXN 高压电网与缺页路由请求 */
struct uxn_trap_req {
    pid_t pid;
    unsigned long orig_page_va; 
    unsigned long recomp_va;    
    u32 offset_map[1024];       /* 物理指令偏移地图 */
};

/* 硬件断点生命周期控制请求 */
struct hwbp_req {
    pid_t tgid;
    unsigned long target_addr;
};

/* Maps 截断隐藏请求 (VMA 退路保护) */
struct hide_vma_req {
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

/* ---------------------------------------------------------
 * Core 模块暴露给 Main 网关的内部接口
 * 实现在 core_hook.c (即前述 Ghost Core V10 源码)
 * --------------------------------------------------------- */
extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);

extern long handle_alloc_ghost(struct ghost_alloc_req *req);
extern long handle_set_uxn_trap(struct uxn_trap_req *req);
extern long handle_set_hwbp(struct hwbp_req *req);
extern long handle_hwbp_gate(struct hwbp_req *req, bool enable);
extern long handle_hide_vma(struct hide_vma_req *req);

#endif /* _SHADOW_HOOK_H */

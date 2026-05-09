#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHOST_MAGIC 'G'

#define IOCTL_CMD_ALLOC_GHOST   _IOWR(GHOST_MAGIC, 1, struct ghost_alloc_req)
#define IOCTL_CMD_SET_UXN_TRAP  _IOW(GHOST_MAGIC, 2, struct uxn_trap_req)
#define IOCTL_CMD_SET_HWBP      _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_CMD_DISABLE_HWBP  _IOW(GHOST_MAGIC, 4, struct hwbp_req)
#define IOCTL_CMD_ENABLE_HWBP   _IOW(GHOST_MAGIC, 5, struct hwbp_req)
#define IOCTL_CMD_HIDE_VMA      _IOW(GHOST_MAGIC, 6, struct hide_vma_req)

struct ghost_alloc_req {
    pid_t pid;                  /* 新增：目标进程PID，用于寄生注入 */
    unsigned long target_va;    
    unsigned long size;         
    void __user *bytecode;      
};

struct uxn_trap_req {
    pid_t pid;
    unsigned long orig_page_va; 
    unsigned long recomp_va;    
    u32 offset_map[1024];       
};

struct hwbp_req {
    pid_t tgid;
    unsigned long target_addr;
};

struct hide_vma_req {
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);

extern long handle_alloc_ghost(struct ghost_alloc_req *req);
extern long handle_set_uxn_trap(struct uxn_trap_req *req);
extern long handle_set_hwbp(struct hwbp_req *req);
extern long handle_hwbp_gate(struct hwbp_req *req, bool enable);
extern long handle_hide_vma(struct hide_vma_req *req);

#endif /* _SHADOW_HOOK_H */

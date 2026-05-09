#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHOST_MAGIC 'G'

/* 废弃原有的零碎 IOCTL，升级为高阶合成指令 */
#define IOCTL_CMD_GET_BASE           _IOWR(GHOST_MAGIC, 7, struct module_base_req)
#define IOCTL_CMD_DEPLOY_SHADOW_PATCH _IOW(GHOST_MAGIC, 8, struct shadow_patch_req)

/* 获取模块基址请求 */
struct module_base_req {
    pid_t pid;
    char mod_name[64];      /* 目标库名，如 libil2cpp.so */
    uint64_t base_addr;     /* 内核返回的基址 */
};

/* 原子化影子页部署请求 */
struct shadow_patch_req {
    pid_t pid;
    uint64_t target_addr;   /* 目标函数的绝对物理地址 */
    uint32_t patch_data[16];/* 汇编载荷 (最大支持 16 条指令) */
    size_t patch_words;     /* 载荷指令数 */
};

extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern long handle_get_module_base(struct module_base_req *req);
extern long handle_deploy_shadow_patch(struct shadow_patch_req *req);

#endif /* _SHADOW_HOOK_H */

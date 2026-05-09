/*
 * =====================================================================================
 *       Filename:  shadow_hook.h
 *    Description:  Ghost Core V10.5 Protocol Definitions (Zero VFS Footprint)
 * =====================================================================================
 */
#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define GHOST_MAGIC 'G'

/* 
 * 高阶合成指令：彻底废除对 /proc 伪文件系统的依赖 
 */
#define IOCTL_CMD_GET_BASE            _IOWR(GHOST_MAGIC, 7, struct module_base_req)
#define IOCTL_CMD_DEPLOY_SHADOW_PATCH _IOW(GHOST_MAGIC, 8, struct shadow_patch_req)
#define IOCTL_CMD_HIDE_VMA            _IOW(GHOST_MAGIC, 6, struct hide_vma_req)

/* Ring 0 内核级基址获取请求 */
struct module_base_req {
    pid_t pid;
    char mod_name[64];      /* 目标库名，如 libil2cpp.so */
    uint64_t base_addr;     /* 由内核遍历 Maple Tree 后返回的基址 */
};

/* 原子化影子页部署请求 (支持单点替换与空闲区 Shellcode 寄生) */
struct shadow_patch_req {
    pid_t pid;
    uint64_t target_addr;       /* 挂钩的目标物理绝对地址 */
    uint32_t patch_data[4];     /* 原地址处替换的指令 (最大 4 条) */
    size_t patch_words;         /* 替换指令的数量 */
    uint32_t payload_data[32];  /* 附加在影子页空闲区(如偏移 +2048)的 Payload */
    size_t payload_words;       /* Payload 指令数量 */
    uint32_t payload_offset;    /* 影子页内的写入偏移，例如 2048 */
};

/* VMA 物理隐身衣请求 */
struct hide_vma_req {
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

/* 核心引擎暴漏给网关的链接符号 */
extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern long handle_get_module_base(struct module_base_req *req);
extern long handle_deploy_shadow_patch(struct shadow_patch_req *req);
extern long handle_hide_vma(struct hide_vma_req *req);

#endif /* _SHADOW_HOOK_H */

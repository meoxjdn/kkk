/*
 * =====================================================================================
 *       Filename:  dynamic_resolver.c
 *    Description:  Bypassing GKI KMI Restrictions via Kprobe Extraction
 *   Architecture:  AArch64
 * =====================================================================================
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include "dynamic_resolver.h"

/* 定义函数指针类型以接收被隐藏的 kallsyms_lookup_name */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t p_kallsyms_lookup_name = NULL;

/* 
 * 战术探针 (Dummy Kprobe)
 * 我们只需利用内核注册 Kprobe 时必须解析符号地址的机制，萃取其 addr 字段
 */
static struct kprobe kp_dummy = {
    .symbol_name = "kallsyms_lookup_name",
};

int ghost_resolver_init(void)
{
    int ret;

    ret = register_kprobe(&kp_dummy);
    if (ret < 0) {
        pr_err("[Ghost Resolver] Failed to register dummy kprobe for kallsyms_lookup_name. Error: %d\n", ret);
        return ret;
    }

    /* 物理地址萃取：此时 kp_dummy.addr 已被内核合法的符号地址填充 */
    p_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_dummy.addr;

    /* 阅后即焚，消除探针痕迹 */
    unregister_kprobe(&kp_dummy);

    if (!p_kallsyms_lookup_name) {
        pr_err("[Ghost Resolver] Fatal: Extracted address is NULL.\n");
        return -EINVAL;
    }

    pr_info("[Ghost Resolver] Engine Online. kallsyms_lookup_name extracted at: 0x%lx\n", 
            (unsigned long)p_kallsyms_lookup_name);

    return 0;
}

void *ghost_resolve_sym(const char *name)
{
    unsigned long addr;

    if (unlikely(!p_kallsyms_lookup_name)) {
        pr_err("[Ghost Resolver] Call failed: Resolver not initialized.\n");
        return NULL;
    }

    addr = p_kallsyms_lookup_name(name);
    if (!addr) {
        pr_warn("[Ghost Resolver] Symbol lookup failed: %s\n", name);
        return NULL;
    }

    return (void *)addr;
}

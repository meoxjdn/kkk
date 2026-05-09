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

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t p_kallsyms_lookup_name = NULL;

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

    p_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_dummy.addr;
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
        return NULL;
    }

    addr = p_kallsyms_lookup_name(name);
    if (!addr) {
        return NULL;
    }

    return (void *)addr;
}

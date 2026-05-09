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
    int ret = register_kprobe(&kp_dummy);
    if (ret < 0) {
        pr_err("[Ghost Resolver] Failed to extract kallsyms_lookup_name.\n");
        return ret;
    }
    p_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_dummy.addr;
    unregister_kprobe(&kp_dummy);

    if (!p_kallsyms_lookup_name) return -EINVAL;
    return 0;
}

void *ghost_resolve_sym(const char *name)
{
    if (!p_kallsyms_lookup_name) return NULL;
    return (void *)p_kallsyms_lookup_name(name);
}

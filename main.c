#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "shadow_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");
MODULE_DESCRIPTION("Android WuWa - Stealth Breakpoint Engine");

/* 定义模块参数，用于接收来自 loader.sh 的地址 */
static unsigned long p_reg_step = 0;
static unsigned long p_unreg_step = 0;
static unsigned long p_en_step = 0;
static unsigned long p_dis_step = 0;
static unsigned long p_fp_pres = 0;
static unsigned long p_fp_upd = 0;
static unsigned long p_reg_brk = 0;
static unsigned long p_unreg_brk = 0;

module_param(p_reg_step, ulong, 0400);
module_param(p_unreg_step, ulong, 0400);
module_param(p_en_step, ulong, 0400);
module_param(p_dis_step, ulong, 0400);
module_param(p_fp_pres, ulong, 0400);
module_param(p_fp_upd, ulong, 0400);
module_param(p_reg_brk, ulong, 0400);
module_param(p_unreg_brk, ulong, 0400);

static int __init wuwa_driver_init(void)
{
    struct shadow_sym_request syms;
    int ret;
    
    pr_info("[android-wuwa] Awakening shadow hook subsystem...\n");
    
    /* 组装地址请求包 */
    syms.p_register_user_step_hook = p_reg_step;
    syms.p_unregister_user_step_hook = p_unreg_step;
    syms.p_user_enable_single_step = p_en_step;
    syms.p_user_disable_single_step = p_dis_step;
    syms.p_fpsimd_preserve_current_state = p_fp_pres;
    syms.p_fpsimd_update_current_state = p_fp_upd;
    syms.p_register_user_break_hook = p_reg_brk;
    syms.p_unregister_user_break_hook = p_unreg_brk;

    ret = shadow_fault_init_dynamic(&syms);
    if (ret < 0) {
        pr_err("[android-wuwa] Initialization failed! Missing core payload.\n");
        return ret;
    }
    
    return 0;
}

static void __exit wuwa_driver_exit(void)
{
    shadow_fault_exit();
    pr_info("[android-wuwa] Module eradicated from kernel space.\n");
}

module_init(wuwa_driver_init);
module_exit(wuwa_driver_exit);

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include "shadow_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");
MODULE_DESCRIPTION("Android WuWa - Stealth Breakpoint Engine");

static unsigned long p_reg_step = 0;
static unsigned long p_unreg_step = 0;
static unsigned long p_en_step = 0;
static unsigned long p_dis_step = 0;
static unsigned long p_fp_pres = 0;
static unsigned long p_fp_upd = 0;
static unsigned long p_reg_brk = 0;
static unsigned long p_unreg_brk = 0;

module_param(p_reg_step, ulong, 0400); module_param(p_unreg_step, ulong, 0400);
module_param(p_en_step, ulong, 0400);  module_param(p_dis_step, ulong, 0400);
module_param(p_fp_pres, ulong, 0400);  module_param(p_fp_upd, ulong, 0400);
module_param(p_reg_brk, ulong, 0400);  module_param(p_unreg_brk, ulong, 0400);

static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (cmd == WUWA_IOCTL_ADD_SHADOW) {
        struct shadow_request req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        return add_shadow(&req);
    } 
    else if (cmd == WUWA_IOCTL_RAW_PATCH) {
        struct raw_patch_req req;
        struct task_struct *task;
        int ret;
        
        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;
        
        rcu_read_lock();
        task = pid_task(find_vpid(req.pid), PIDTYPE_PID);
        if (task) get_task_struct(task);
        rcu_read_unlock();
        if (!task) return -ESRCH;
        
        /* 无视内存保护，强力穿透写入 */
        ret = access_process_vm(task, req.addr, &req.data, 4, FOLL_WRITE | FOLL_FORCE);
        put_task_struct(task);
        return (ret == 4) ? 0 : -EFAULT;
    }
    return -EINVAL;
}

static const struct file_operations wuwa_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = wuwa_ioctl,
    .compat_ioctl   = wuwa_ioctl,
};

static struct miscdevice wuwa_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "wuwa_core",
    .fops  = &wuwa_fops,
};

static int __init wuwa_driver_init(void)
{
    struct shadow_sym_request syms;
    int ret;
    
    pr_info("[android-wuwa] Awakening shadow hook subsystem...\n");
    
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
        pr_err("[android-wuwa] Core init failed: %d\n", ret);
        return ret;
    }
    
    ret = misc_register(&wuwa_misc);
    if (ret < 0) {
        pr_err("[android-wuwa] Misc device register failed: %d\n", ret);
        shadow_fault_exit();
        return ret;
    }
    
    pr_info("[android-wuwa] Device /dev/wuwa_core is ready.\n");
    return 0;
}

static void __exit wuwa_driver_exit(void)
{
    misc_deregister(&wuwa_misc);
    shadow_fault_exit();
    pr_info("[android-wuwa] Module eradicated.\n");
}

module_init(wuwa_driver_init);
module_exit(wuwa_driver_exit);

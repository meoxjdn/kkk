/*
 * =====================================================================================
 *       Filename:  main.c
 *    Description:  Ghost Core V10.11 Gateway Manager
 * =====================================================================================
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "shadow_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");
MODULE_DESCRIPTION("Ghost Core V10.11 Gateway");

static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_CMD_GET_PID: {
            struct get_pid_req pid_req;
            if (copy_from_user(&pid_req, (void __user *)arg, sizeof(pid_req))) return -EFAULT;
            long ret = handle_get_pid(&pid_req);
            if (ret == 0 && copy_to_user((void __user *)arg, &pid_req, sizeof(pid_req))) return -EFAULT;
            return ret;
        }

        case IOCTL_CMD_GET_BASE: {
            struct module_base_req base_req;
            if (copy_from_user(&base_req, (void __user *)arg, sizeof(base_req))) return -EFAULT;
            if (handle_get_module_base(&base_req) == 0) {
                if (copy_to_user((void __user *)arg, &base_req, sizeof(base_req))) return -EFAULT;
                return 0;
            }
            return -ESRCH;
        }

        case IOCTL_SET_HWBP:
        case IOCTL_PAUSE_HWBP:
        case IOCTL_RESUME_HWBP: {
            /* 
             * 核心路由下沉：所有涉及 HWBP 的指令连同结构体指针
             * 一并转交 core_hook.c 进行拆包和处理。
             */
            return handle_hwbp_ioctl(cmd, arg);
        }

        default:
            pr_warn("[Ghost Gateway] Unknown IOCTL vector intercepted: 0x%x\n", cmd);
            return -ENOTTY;
    }
}

static const struct file_operations wuwa_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = wuwa_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = wuwa_ioctl,
#endif
};

static struct miscdevice wuwa_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "wuwa_core",
    .fops  = &wuwa_fops,
};

static int __init wuwa_driver_init(void)
{
    int ret;
    pr_info("[Ghost Gateway] Booting V10.11 State-Machine Orchestrator...\n");

    ret = ghost_core_init_engine();
    if (ret < 0) {
        pr_err("[Ghost Gateway] Failed to ignite Core Engine. Aborting sequence.\n");
        return ret;
    }
    
    ret = misc_register(&wuwa_misc);
    if (ret < 0) {
        ghost_core_exit_engine();
        pr_err("[Ghost Gateway] VFS device registration failed. Kernel locked.\n");
        return ret;
    }

    pr_info("[Ghost Gateway] Engine Online. IOCTL Router active on /dev/wuwa_core.\n");
    return 0;
}

static void __exit wuwa_driver_exit(void)
{
    misc_deregister(&wuwa_misc);
    ghost_core_exit_engine();
    pr_info("[Ghost Gateway] Gateway Offline. HWBP resources wiped. Trace erased.\n");
}

module_init(wuwa_driver_init);
module_exit(wuwa_driver_exit);

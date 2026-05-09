/*
 * =====================================================================================
 *       Filename:  main.c
 *    Description:  Ghost Core V10.5 Gateway Manager
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
MODULE_DESCRIPTION("Ghost Core V10.5 Gateway");

/* 
 * 极客网关：将来自用户态的 IOCTL 精准路由至 V10.5 核心物理引擎。
 * 负责严格的用户态内存跨界边界校验。
 */
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_CMD_GET_BASE: {
            struct module_base_req base_req;
            if (copy_from_user(&base_req, (void __user *)arg, sizeof(base_req))) {
                return -EFAULT;
            }
            if (handle_get_module_base(&base_req) == 0) {
                if (copy_to_user((void __user *)arg, &base_req, sizeof(base_req))) {
                    return -EFAULT;
                }
                return 0;
            }
            return -ESRCH;
        }

        case IOCTL_CMD_DEPLOY_SHADOW_PATCH: {
            struct shadow_patch_req patch_req;
            if (copy_from_user(&patch_req, (void __user *)arg, sizeof(patch_req))) {
                return -EFAULT;
            }
            return handle_deploy_shadow_patch(&patch_req);
        }

        case IOCTL_CMD_HIDE_VMA: {
            struct hide_vma_req hide_req;
            if (copy_from_user(&hide_req, (void __user *)arg, sizeof(hide_req))) {
                return -EFAULT;
            }
            return handle_hide_vma(&hide_req);
        }

        default:
            pr_warn("[WuWa Gateway] Unknown IOCTL command received: 0x%x\n", cmd);
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
    pr_info("[WuWa] Booting V10.5 Zero-Footprint Gateway...\n");

    ret = ghost_core_init_engine();
    if (ret < 0) {
        pr_err("[WuWa] Failed to initialize Ghost Core Engine. Aborting.\n");
        return ret;
    }
    
    ret = misc_register(&wuwa_misc);
    if (ret < 0) {
        ghost_core_exit_engine();
        pr_err("[WuWa] Failed to register misc device.\n");
        return ret;
    }

    pr_info("[WuWa] V10.5 Gateway Online. Listening on /dev/wuwa_core\n");
    return 0;
}

static void __exit wuwa_driver_exit(void)
{
    misc_deregister(&wuwa_misc);
    ghost_core_exit_engine();
    pr_info("[WuWa] Gateway Offline. System cleanly restored.\n");
}

module_init(wuwa_driver_init);
module_exit(wuwa_driver_exit);

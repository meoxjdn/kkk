#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "shadow_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");
MODULE_DESCRIPTION("Android WuWa - Ghost Core V10 Gateway");

/* 
 * 极客网关：将来自用户态的 IOCTL 精准路由至 V10 核心物理引擎。
 * 这里负责严格的用户态内存跨界校验 (copy_from_user)。
 */
static long wuwa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ghost_alloc_req alloc_req;
    struct uxn_trap_req trap_req;
    struct hwbp_req hwbp_r;
    struct hide_vma_req hide_req;

    switch (cmd) {
    case IOCTL_CMD_ALLOC_GHOST:
        if (copy_from_user(&alloc_req, (void __user *)arg, sizeof(alloc_req)))
            return -EFAULT;
        return handle_alloc_ghost(&alloc_req);

    case IOCTL_CMD_SET_UXN_TRAP:
        if (copy_from_user(&trap_req, (void __user *)arg, sizeof(trap_req)))
            return -EFAULT;
        return handle_set_uxn_trap(&trap_req);

    case IOCTL_CMD_SET_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r)))
            return -EFAULT;
        return handle_set_hwbp(&hwbp_r);

    case IOCTL_CMD_DISABLE_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r)))
            return -EFAULT;
        return handle_hwbp_gate(&hwbp_r, false);

    case IOCTL_CMD_ENABLE_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r)))
            return -EFAULT;
        return handle_hwbp_gate(&hwbp_r, true);

    case IOCTL_CMD_HIDE_VMA:
        if (copy_from_user(&hide_req, (void __user *)arg, sizeof(hide_req)))
            return -EFAULT;
        return handle_hide_vma(&hide_req);

    default:
        pr_warn("[WuWa Gateway] Unknown IOCTL command: 0x%x\n", cmd);
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
    .name  = "wuwa_core",   /* 保持你原有的设备名，避免用户态改代码 */
    .fops  = &wuwa_fops,
};

static int __init wuwa_driver_init(void)
{
    int ret;
    pr_info("[WuWa] Booting V10 Gateway...\n");

    /* 唤醒并装载 V10 底层物理劫持引擎 */
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

    pr_info("[WuWa] V10 Gateway Online. Listening on /dev/wuwa_core\n");
    return 0;
}

static void __exit wuwa_driver_exit(void)
{
    /* 先注销设备入口，阻断新的请求进入 */
    misc_deregister(&wuwa_misc);
    
    /* 触发 V10 的绝对排干与安全卸载序列 */
    ghost_core_exit_engine();
    
    pr_info("[WuWa] Gateway Offline. System cleanly restored.\n");
}

module_init(wuwa_driver_init);
module_exit(wuwa_driver_exit);

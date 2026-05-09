/*
 * =====================================================================================
 *       Filename:  main.c
 *    Description:  Ghost Core Gateway (VFS Device Orchestrator)
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
MODULE_DESCRIPTION("Ghost Core Stealth Gateway");

static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req req;
    int ret;
    
    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;
    
    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) {
            return -EFAULT;
        }
        ret = wuwa_install_perf_hbp(&req);
        if (ret < 0) return ret;
    } 
    else if (pkt.cmd_id == CMD_HBP_CLEANUP) {
        wuwa_cleanup_perf_hbp();
    }
    
    return count;
}

static const struct file_operations core_fops = {
    .owner = THIS_MODULE,
    .write = core_write,
};

static struct miscdevice core_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "logd_service",
    .fops  = &core_fops,
};

static int __init wuwa_hbp_init_module(void) {
    int ret;

    ret = ghost_core_init_engine();
    if (ret < 0) {
        pr_err("[WuWa Gateway] Core engine failed to ignite. Err: %d\n", ret);
        return ret;
    }

    ret = misc_register(&core_misc);
    if (ret < 0) {
        ghost_core_exit_engine();
        pr_err("[WuWa Gateway] Failed to register misc device.\n");
        return ret;
    }

    pr_info("[WuWa Gateway] Stealth VFS Gateway Online.\n");
    return 0;
}

static void __exit wuwa_hbp_cleanup_module(void) {
    misc_deregister(&core_misc);
    ghost_core_exit_engine();
    pr_info("[WuWa Gateway] Traces erased cleanly.\n");
}

module_init(wuwa_hbp_init_module);
module_exit(wuwa_hbp_cleanup_module);

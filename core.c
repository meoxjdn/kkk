/*
 * Ghost core: a small, observable control plane for an Android kernel module.
 *
 * INSTALL records a target and its configuration. MEM_READ uses the MM
 * subsystem through access_process_vm(). No kernel text, user page table, or
 * exception return path is modified by this module.
 */
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <asm/ptrace.h>
#include "dynamic_resolver.h"
#include "shadow_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kkk");
MODULE_DESCRIPTION("Ghost control plane with safe memory inspection");

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable verbose logging (0/1)");

#define NETLINK_WUWA_MAX   29

#define GHOST_MAX_READ     4096U
#define GHOST_PATCH_NONE   0
#define GHOST_PATCH_READY  1

#ifndef TASK_SIZE_MAX
#define TASK_SIZE_MAX TASK_SIZE_64
#endif

typedef int (*access_process_vm_t)(struct task_struct *, unsigned long,
                                   void *, int, unsigned int);
static access_process_vm_t fn_access_process_vm;

static struct sock *wuwa_nl_sk;
static int wuwa_nl_proto;
static DEFINE_MUTEX(g_lock);
static struct mm_struct *g_target_mm;
static struct wuwa_hbp_req g_cfg;
static int g_target_tid;
static int g_target_tgid;
static int g_install_rc = -ENODEV;
static int g_patch_state;
static atomic64_t g_hit_count = ATOMIC64_INIT(0);

/* Optional observer. It never changes fault handling or register state. */
static struct kprobe g_fault_probe;
static bool g_fault_probe_registered;

static int ghost_fault_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    (void)regs;
    if (READ_ONCE(g_patch_state) != GHOST_PATCH_READY || !g_target_tgid)
        return 0;
    if (current->tgid == READ_ONCE(g_target_tgid))
        atomic64_inc(&g_hit_count);
    return 0;
}

static int ghost_send(u32 portid, u32 seq, u16 type,
                      const void *data, size_t len)
{
    struct sk_buff *reply;
    struct nlmsghdr *nlh;
    int rc;

    reply = nlmsg_new(len, GFP_KERNEL);
    if (!reply)
        return -ENOMEM;
    nlh = nlmsg_put(reply, portid, seq, type, len, 0);
    if (!nlh) {
        kfree_skb(reply);
        return -EMSGSIZE;
    }
    if (len)
        memcpy(nlmsg_data(nlh), data, len);
    rc = netlink_unicast(wuwa_nl_sk, reply, portid, MSG_DONTWAIT);
    return rc < 0 ? rc : 0;
}

static int ghost_read_task_mem(struct task_struct *task, unsigned long addr,
                               void *dst, size_t size)
{
    size_t first;
    int ret;

    if (!task || !dst || !size || addr >= TASK_SIZE_MAX)
        return -EINVAL;
    if (size > GHOST_MAX_READ || size > TASK_SIZE_MAX - addr)
        return -EINVAL;
    if (!fn_access_process_vm)
        return -EOPNOTSUPP;
    first = min_t(size_t, size, PAGE_SIZE - (addr & ~PAGE_MASK));
    ret = fn_access_process_vm(task, addr, dst, (int)first, FOLL_FORCE);
    return ret > 0 ? ret : -EFAULT;
}

static bool ghost_valid_target(const struct wuwa_hbp_req *req, uint64_t off)
{
    return off <= (uint64_t)(TASK_SIZE_MAX - req->base_addr) &&
           req->base_addr + off < TASK_SIZE_MAX &&
           !((req->base_addr + off) & 3);
}

static int ghost_validate_req(const struct wuwa_hbp_req *req)
{
    if (!req || req->tid <= 0 || !req->base_addr ||
        req->base_addr >= TASK_SIZE_MAX)
        return -EINVAL;
    if (!req->border_on && !req->skip_on && !req->damage_on &&
        !req->maxhp_on && !req->fov_on)
        return -EINVAL;
    if ((req->border_on && !ghost_valid_target(req, req->off_border)) ||
        (req->skip_on && (!ghost_valid_target(req, req->off_pause_win) ||
                          !ghost_valid_target(req, req->off_pause_jmp))) ||
        (req->damage_on && !ghost_valid_target(req, req->off_damage)) ||
        (req->fov_on && (!ghost_valid_target(req, req->off_fov) ||
                         !ghost_valid_target(req, req->off_fov_gadget))) ||
        (req->maxhp_on && !ghost_valid_target(req, req->off_kill)))
        return -EINVAL;
    return 0;
}

static int ghost_install(const struct wuwa_hbp_req *req)
{
    struct pid *pid;
    struct task_struct *task;
    struct mm_struct *mm;
    int rc;

    rc = ghost_validate_req(req);
    if (rc)
        return rc;
    pid = find_get_pid(req->tid);
    if (!pid)
        return -ESRCH;
    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -ESRCH;
    }

    mutex_lock(&g_lock);
    if (g_target_tgid && g_target_tgid != task->tgid) {
        rc = -EBUSY;
        mmput(mm);
    } else {
        if (g_target_mm)
            mmput(g_target_mm);
        g_target_mm = mm;
        memcpy(&g_cfg, req, sizeof(g_cfg));
        g_target_tid = task->pid;
        g_target_tgid = task->tgid;
        g_install_rc = 0;
        g_patch_state = GHOST_PATCH_READY;
        atomic64_set(&g_hit_count, 0);
        rc = 0;
    }
    mutex_unlock(&g_lock);
    put_task_struct(task);
    if (debug)
        pr_info("ghost: install tid=%d rc=%d state=%d\n",
                req->tid, rc, READ_ONCE(g_patch_state));
    return rc;
}

static void ghost_cleanup(void)
{
    struct mm_struct *mm;

    mutex_lock(&g_lock);
    g_patch_state = GHOST_PATCH_NONE;
    g_install_rc = -ENODEV;
    g_target_tid = 0;
    g_target_tgid = 0;
    memset(&g_cfg, 0, sizeof(g_cfg));
    mm = g_target_mm;
    g_target_mm = NULL;
    mutex_unlock(&g_lock);
    if (mm)
        mmput(mm);
}

static void ghost_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int len;

    if (!skb)
        return;
    nlh = nlmsg_hdr(skb);
    len = skb->len;
    while (nlmsg_ok(nlh, len)) {
        u32 portid = NETLINK_CB(skb).portid;
        u32 seq = nlh->nlmsg_seq;

        switch (nlh->nlmsg_type) {
        case CMD_PING:
            ghost_send(portid, seq, CMD_PONG, NULL, 0);
            break;
        case CMD_HBP_INSTALL: {
            struct wuwa_hbp_ack ack = { .rc = -EINVAL, .tid = 0 };
            struct wuwa_hbp_pkt pkt;
            size_t i;

            if (nlmsg_len(nlh) == sizeof(pkt)) {
                memcpy(&pkt, nlmsg_data(nlh), sizeof(pkt));
                for (i = 0; i < sizeof(pkt.payload); i++)
                    ((u8 *)&pkt.payload)[i] ^= ((u8 *)&pkt.seed)[i % 4];
                ack.tid = pkt.payload.tid;
                ack.rc = ghost_install(&pkt.payload);
            }
            ghost_send(portid, seq, CMD_HBP_ACK, &ack, sizeof(ack));
            break;
        }
        case CMD_HBP_CLEANUP:
            ghost_cleanup();
            break;
        case CMD_STATUS: {
            struct wuwa_status_ack status;
            mutex_lock(&g_lock);
            status.install_rc = g_install_rc;
            status.patch_state = g_patch_state;
            status.tid = g_target_tid;
            status.tgid = g_target_tgid;
            status.hit_count = atomic64_read(&g_hit_count);
            mutex_unlock(&g_lock);
            ghost_send(portid, seq, CMD_STATUS_ACK,
                       &status, sizeof(status));
            break;
        }
        case CMD_MEM_READ: {
            struct wuwa_mem_req req;
            struct pid *pid;
            struct task_struct *task;
            struct sk_buff *reply;
            struct nlmsghdr *reply_nlh;
            struct wuwa_mem_req *out;
            size_t payload_len = 0;

            if (nlmsg_len(nlh) != sizeof(req))
                break;
            memcpy(&req, nlmsg_data(nlh), sizeof(req));
            req.size = min_t(u32, req.size, GHOST_MAX_READ);
            reply = nlmsg_new(sizeof(req) + req.size, GFP_KERNEL);
            if (!reply)
                break;
            reply_nlh = nlmsg_put(reply, portid, seq, CMD_MEM_READ_ACK,
                                  sizeof(req) + req.size, 0);
            if (!reply_nlh) {
                kfree_skb(reply);
                break;
            }
            out = nlmsg_data(reply_nlh);
            *out = req;
            out->size = 0;
            pid = find_get_pid(req.pid);
            task = pid ? get_pid_task(pid, PIDTYPE_PID) : NULL;
            if (pid)
                put_pid(pid);
            if (task) {
                bool allowed;
                mutex_lock(&g_lock);
                allowed = g_target_tgid && task->tgid == g_target_tgid;
                mutex_unlock(&g_lock);
                if (allowed) {
                    int got = ghost_read_task_mem(task, req.addr, out + 1,
                                                  req.size);
                    if (got > 0) {
                        out->size = got;
                        payload_len = got;
                    }
                }
                put_task_struct(task);
            }
            reply_nlh->nlmsg_len = NLMSG_LENGTH(sizeof(req) + payload_len);
            netlink_unicast(wuwa_nl_sk, reply, portid, MSG_DONTWAIT);
            break;
        }
        default:
            break;
        }
        nlh = nlmsg_next(nlh, &len);
    }
}

static int __init ghost_core_init(void)
{
    struct netlink_kernel_cfg cfg = { .input = ghost_nl_recv_msg };

    if (ghost_resolver_init() < 0)
        return -ENOSYS;
    fn_access_process_vm = (access_process_vm_t)ghost_resolve_sym("access_process_vm");
    if (!fn_access_process_vm)
        pr_warn("ghost: access_process_vm unavailable; MEM_READ disabled\n");

    wuwa_nl_sk = NULL;
    for (wuwa_nl_proto = NETLINK_WUWA; wuwa_nl_proto <= NETLINK_WUWA_MAX;
         wuwa_nl_proto++) {
        wuwa_nl_sk = netlink_kernel_create(&init_net, wuwa_nl_proto, &cfg);
        if (wuwa_nl_sk)
            break;
    }
    if (!wuwa_nl_sk)
        return -ENOMEM;

    memset(&g_fault_probe, 0, sizeof(g_fault_probe));
    g_fault_probe.symbol_name = "do_page_fault";
    g_fault_probe.pre_handler = ghost_fault_pre_handler;
    if (!register_kprobe(&g_fault_probe)) {
        g_fault_probe_registered = true;
        pr_info("ghost: fault observer enabled\n");
    } else {
        pr_info("ghost: fault observer unavailable\n");
    }
    pr_info("ghost: netlink proto %d registered\n", wuwa_nl_proto);
    return 0;
}

static void __exit ghost_core_exit(void)
{
    if (g_fault_probe_registered) {
        unregister_kprobe(&g_fault_probe);
        g_fault_probe_registered = false;
    }
    ghost_cleanup();
    if (wuwa_nl_sk) {
        netlink_kernel_release(wuwa_nl_sk);
        wuwa_nl_sk = NULL;
    }
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

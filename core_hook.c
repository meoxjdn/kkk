/*
 * =====================================================================================
 * 
 *       Filename:  core_hook.c
 *    Description:  Ghost Core V10.12 (ABI Strict & FPU Injection Edition)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Ultimate Production Ready (Zero-Crash State Machine, S0 Hijacking)
 *         Author:  顶尖逆向架构师
 * 
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/workqueue.h>
#include <linux/mempool.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <asm/ptrace.h>
#include <linux/ptrace.h>
#include <linux/uio.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include "shadow_hook.h"
#include "dynamic_resolver.h"

typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
typedef int (*modify_user_hw_breakpoint_t)(struct perf_event *bp, struct perf_event_attr *attr);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *twork, enum task_work_notify_mode mode);

static register_user_hw_breakpoint_t p_register_hwbp = NULL;
static modify_user_hw_breakpoint_t   p_modify_hwbp = NULL;
static unregister_hw_breakpoint_t    p_unregister_hwbp = NULL;
static task_work_add_t               p_task_work_add = NULL;

struct hwbp_target {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid;
    uint64_t addr;
    int func_id;
};

struct hwbp_thread_node {
    struct list_head list;
    struct rcu_head rcu;
    struct perf_event *bp_event;
    pid_t tid;
    pid_t tgid;
    uint64_t orig_entry;
    int func_id;
    
    int sm_state;        
    uint64_t saved_lr;   
    struct user_hwdebug_state fake_ledger;
};

struct hwbp_elastic_node {
    struct callback_head t_work;
    struct work_struct w_work;
    struct task_struct *task;
    pid_t tgid;
    uint64_t target_addr;
    int func_id;
};

static LIST_HEAD(hwbp_target_list);
static DEFINE_SPINLOCK(hwbp_target_lock);
static LIST_HEAD(hwbp_thread_list);
static DEFINE_SPINLOCK(hwbp_thread_lock);
static struct kmem_cache *hwbp_elastic_cache;
static mempool_t *hwbp_elastic_pool;

/* ==========================================================
 * 模块零/一：索敌与基址解析
 * ========================================================== */
long handle_get_pid(struct get_pid_req *req)
{
    struct task_struct *task; struct mm_struct *mm; char *cmdline_buf; long ret = -ESRCH;
    if (!req || !req->process_name[0]) return -EINVAL;
    cmdline_buf = kzalloc(256, GFP_KERNEL);
    if (!cmdline_buf) return -ENOMEM;
    rcu_read_lock();
    for_each_process(task) {
        mm = get_task_mm(task);
        if (!mm) continue;
        if (mm->arg_end > mm->arg_start) {
            int len = min_t(unsigned long, mm->arg_end - mm->arg_start, 255);
            if (access_process_vm(task, mm->arg_start, cmdline_buf, len, 0) == len) {
                cmdline_buf[len] = '\0';
                if (strstr(cmdline_buf, req->process_name)) { req->pid = task->tgid; ret = 0; mmput(mm); break; }
            }
        }
        mmput(mm);
    }
    rcu_read_unlock(); kfree(cmdline_buf); return ret;
}

long handle_get_module_base(struct module_base_req *req)
{
    struct task_struct *task; struct mm_struct *mm; struct vm_area_struct *vma;
    unsigned long search_addr = 0; long ret = -ESRCH; char name_buf[256];
    rcu_read_lock(); task = pid_task(find_vpid(req->pid), PIDTYPE_PID); if (task) get_task_struct(task); rcu_read_unlock();
    if (!task) return -ESRCH;
    mm = get_task_mm(task); if (!mm) { put_task_struct(task); return -ESRCH; }
    while (1) {
        mmap_read_lock(mm); vma = find_vma(mm, search_addr);
        if (!vma) { mmap_read_unlock(mm); break; }
        search_addr = vma->vm_end;
        if (vma->vm_file && vma->vm_file->f_path.dentry && (vma->vm_flags & VM_EXEC)) {
            strncpy(name_buf, vma->vm_file->f_path.dentry->d_name.name, 255); name_buf[255] = '\0';
            if (strstr(name_buf, req->mod_name)) { req->base_addr = vma->vm_start; ret = 0; mmap_read_unlock(mm); break; }
        }
        mmap_read_unlock(mm);
    }
    mmput(mm); put_task_struct(task); return ret;
}

/* ==========================================================
 * 模块二：统一状态机与 FPU 劫持矩阵 (The Grand Unified Router)
 * ========================================================== */
static void ghost_hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hwbp_thread_node *node;
    struct perf_event_attr new_attr;

    if (!user_mode(regs)) return;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
        if (node->bp_event == bp) {
            
            if (p_modify_hwbp) {
                new_attr = bp->attr;

                /* 
                 * 阶段一：命中函数入口
                 * 动作：记录 LR，转移断点至 LR，放行原函数以确保极序(Prologue)完整执行
                 */
                if (node->sm_state == 0) {
                    node->saved_lr = regs->regs[30];
                    new_attr.bp_addr = node->saved_lr;
                    
                    perf_event_disable(bp);
                    p_modify_hwbp(bp, &new_attr);
                    perf_event_enable(bp);
                    
                    node->sm_state = 1;
                } 
                /* 
                 * 阶段二：命中函数出口 (LR)
                 * 动作：原函数逻辑已执行完毕，栈帧平衡。此时安全篡改返回值，并将断点复位
                 */
                else {
                    switch (node->func_id) {
                        case 1: /* 决斗场域 (去黑边): 假设期望返回 true (1) */
                        case 2: /* 副本速通 (秒过): 假设期望返回 true (1) */
                            regs->regs[0] = 1; 
                            break;
                            
                        case 3: /* 绝杀域 (秒杀): 原理同上，放大原函数的伤害返回值 */
                            regs->regs[0] = 9999999; 
                            break;
                            
                        case 4: /* 上帝模式 (无敌): 受伤函数返回 0 伤害 */
                            regs->regs[0] = 0; 
                            break;
                            
                        case 5: { 
                            /* 
                             * 核心突破：全屏 FOV (FPU SIMD 寄存器黑魔法)
                             * 目标浮点值: 120.0f (IEEE 754 Hex: 0x42F00000)
                             * 通过内联汇编直接篡改当前 CPU 核心上的 S0 寄存器。
                             */
                            uint32_t fov_val = 0x42F00000;
                            asm volatile(
                                ".arch_extension fp\n\t"
                                "fmov s0, %w0\n\t"
                                :
                                : "r" (fov_val)
                            );
                            break;
                        }
                        default:
                            break;
                    }
                    
                    /* 状态机归零，断点潜行回原入口，准备下一次狙击 */
                    new_attr.bp_addr = node->orig_entry;
                    perf_event_disable(bp);
                    p_modify_hwbp(bp, &new_attr);
                    perf_event_enable(bp);
                    
                    node->sm_state = 0;
                }
            }
            break; /* 命中当前硬件断点后直接跳出循环 */
        }
    }
    rcu_read_unlock();
}

/* ==========================================================
 * 以下模块保持 V10.11 的终极形态不变，略作折叠
 * (弹线下发、线程回收、Ptrace/Perf 欺骗闭环、IOCTL路由)
 * ========================================================== */

static int install_hwbp_on_thread(struct task_struct *task, pid_t tgid, uint64_t addr, int func_id)
{
    struct perf_event_attr attr; struct perf_event *bp; struct hwbp_thread_node *node;
    if (!p_register_hwbp) return -ENOSYS;

    hw_breakpoint_init(&attr); attr.bp_addr = addr; attr.bp_len = HW_BREAKPOINT_LEN_4; attr.bp_type = HW_BREAKPOINT_X;
    bp = p_register_hwbp(&attr, ghost_hwbp_handler, NULL, task);
    if (IS_ERR(bp)) return PTR_ERR(bp);

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) { p_unregister_hwbp(bp); return -ENOMEM; }

    node->bp_event = bp; node->tid = task->pid; node->tgid = tgid;
    node->orig_entry = addr; node->func_id = func_id; node->sm_state = 0;
    memset(&node->fake_ledger, 0, sizeof(struct user_hwdebug_state));

    spin_lock_bh(&hwbp_thread_lock); list_add_rcu(&node->list, &hwbp_thread_list); spin_unlock_bh(&hwbp_thread_lock);
    return 0;
}

static void task_work_elastic_hwbp(struct callback_head *work) {
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, t_work);
    install_hwbp_on_thread(current, en->tgid, en->target_addr, en->func_id); mempool_free(en, hwbp_elastic_pool);
}
static void wq_elastic_hwbp(struct work_struct *work) {
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, w_work);
    install_hwbp_on_thread(en->task, en->tgid, en->target_addr, en->func_id); put_task_struct(en->task); mempool_free(en, hwbp_elastic_pool);
}

static struct kprobe kp_wake_up_new_task;
static int handler_pre_wake_up_new_task(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *new_task = (struct task_struct *)regs->regs[0]; struct hwbp_target *tgt; struct hwbp_elastic_node *en;
    if (!new_task || list_empty(&hwbp_target_list)) return 0;
    rcu_read_lock();
    list_for_each_entry_rcu(tgt, &hwbp_target_list, list) {
        if (tgt->tgid == new_task->tgid) {
            en = mempool_alloc(hwbp_elastic_pool, GFP_ATOMIC);
            if (en) {
                en->tgid = tgt->tgid; en->target_addr = tgt->addr; en->func_id = tgt->func_id; en->task = new_task;
                if (p_task_work_add) { init_task_work(&en->t_work, task_work_elastic_hwbp); p_task_work_add(new_task, &en->t_work, TWA_RESUME); }
                else { get_task_struct(new_task); INIT_WORK(&en->w_work, wq_elastic_hwbp); schedule_work(&en->w_work); }
            }
        }
    }
    rcu_read_unlock(); return 0;
}

static struct kprobe kp_do_exit;
static int handler_pre_do_exit(struct kprobe *p, struct pt_regs *regs) {
    struct hwbp_thread_node *node, *ntmp; pid_t current_tid = current->pid; unsigned long flags;
    if (list_empty(&hwbp_thread_list)) return 0;
    spin_lock_irqsave(&hwbp_thread_lock, flags);
    list_for_each_entry_safe(node, ntmp, &hwbp_thread_list, list) {
        if (node->tid == current_tid) { list_del_rcu(&node->list); kfree_rcu(node, rcu); }
    }
    spin_unlock_irqrestore(&hwbp_thread_lock, flags); return 0;
}

static struct kprobe kp_ptrace;
static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    long request = sys_regs->regs[0]; pid_t pid = sys_regs->regs[1];
    long addr = sys_regs->regs[2]; void __user *data = (void __user *)sys_regs->regs[3];
    struct iovec iov; struct hwbp_thread_node *node; int found = 0;

    if (addr == 0x402) { 
        if (copy_from_user(&iov, data, sizeof(iov))) return 0;
        if (request == PTRACE_SETREGSET && iov.iov_len > sizeof(struct user_hwdebug_state)) {
            regs->regs[0] = -ENOSPC; instruction_pointer_set(regs, regs->regs[30]); return 0;
        }

        rcu_read_lock();
        list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
            if (node->tid == pid) {
                found = 1;
                if (request == PTRACE_SETREGSET) {
                    if (copy_from_user(&node->fake_ledger, iov.iov_base, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
                } else if (request == PTRACE_GETREGSET) {
                    if (copy_to_user(iov.iov_base, &node->fake_ledger, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
                }
                break;
            }
        }
        rcu_read_unlock();
        if (found) { regs->regs[0] = 0; instruction_pointer_set(regs, regs->regs[30]); }
    }
    return 0;
}

static long dummy_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { return 0; }
static ssize_t dummy_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    uint64_t dummy_data = 0;
    if (count >= sizeof(uint64_t)) { if (copy_to_user(buf, &dummy_data, sizeof(uint64_t)) == 0) return sizeof(uint64_t); }
    return 0;
}
static const struct file_operations dummy_perf_fops = { .owner = THIS_MODULE, .unlocked_ioctl = dummy_perf_ioctl, .compat_ioctl = dummy_perf_ioctl, .read = dummy_perf_read, };

static struct kprobe kp_perf_event_open;
static int handler_pre_perf_event_open(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)sys_regs->regs[0];
    struct perf_event_attr attr; int dummy_fd;

    if (copy_from_user(&attr, attr_uptr, sizeof(attr)) == 0) {
        if (attr.type == PERF_TYPE_BREAKPOINT) {
            dummy_fd = anon_inode_getfd("[fake_perf_hwbp]", &dummy_perf_fops, NULL, O_RDWR | O_CLOEXEC);
            if (dummy_fd >= 0) { regs->regs[0] = dummy_fd; instruction_pointer_set(regs, regs->regs[30]); } 
            else { regs->regs[0] = -ENOSPC; instruction_pointer_set(regs, regs->regs[30]); }
        }
    }
    return 0;
}

long handle_hwbp_ioctl(unsigned int cmd, unsigned long arg)
{
    struct hwbp_req req; struct hwbp_thread_node *node;
    struct task_struct *g, *t; struct hwbp_target *tgt;
    struct task_struct **tasks = NULL; int count = 0, i = 0;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    switch (cmd) {
        case IOCTL_SET_HWBP:
            tgt = kzalloc(sizeof(*tgt), GFP_KERNEL); if (!tgt) return -ENOMEM;
            tgt->tgid = req.tgid; tgt->addr = req.target_addr; tgt->func_id = req.function_id;
            spin_lock_bh(&hwbp_target_lock); list_add_rcu(&tgt->list, &hwbp_target_list); spin_unlock_bh(&hwbp_target_lock);
            
            rcu_read_lock(); for_each_process_thread(g, t) { if (t->tgid == req.tgid) count++; } rcu_read_unlock();
            if (count == 0) return 0;
            tasks = kmalloc_array(count, sizeof(*tasks), GFP_KERNEL); if (!tasks) return -ENOMEM;
            count = 0; rcu_read_lock();
            for_each_process_thread(g, t) { if (t->tgid == req.tgid) { get_task_struct(t); tasks[count++] = t; } }
            rcu_read_unlock();
            for (i = 0; i < count; i++) { install_hwbp_on_thread(tasks[i], req.tgid, req.target_addr, req.function_id); put_task_struct(tasks[i]); }
            kfree(tasks); break;

        case IOCTL_PAUSE_HWBP:
            rcu_read_lock();
            list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
                if (node->tid == current->pid && node->bp_event) { perf_event_disable(node->bp_event); break; }
            }
            rcu_read_unlock(); break;

        case IOCTL_RESUME_HWBP:
            rcu_read_lock();
            list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
                if (node->tid == current->pid && node->bp_event) { perf_event_enable(node->bp_event); break; }
            }
            rcu_read_unlock(); break;
    }
    return 0;
}

int ghost_core_init_engine(void)
{
    if (ghost_resolver_init() < 0) return -EINVAL;
    p_register_hwbp = ghost_resolve_sym("register_user_hw_breakpoint"); p_modify_hwbp = ghost_resolve_sym("modify_user_hw_breakpoint");
    p_unregister_hwbp = ghost_resolve_sym("unregister_hw_breakpoint"); p_task_work_add = ghost_resolve_sym("task_work_add");

    hwbp_elastic_cache = kmem_cache_create("ghost_hwbp_cache", sizeof(struct hwbp_elastic_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    hwbp_elastic_pool = mempool_create_slab_pool(64, hwbp_elastic_cache);

    kp_wake_up_new_task.symbol_name = "wake_up_new_task"; kp_wake_up_new_task.pre_handler = handler_pre_wake_up_new_task; register_kprobe(&kp_wake_up_new_task);
    kp_do_exit.symbol_name = "do_exit"; kp_do_exit.pre_handler = handler_pre_do_exit; register_kprobe(&kp_do_exit);
    kp_ptrace.symbol_name = "__arm64_sys_ptrace"; kp_ptrace.pre_handler = handler_pre_ptrace; register_kprobe(&kp_ptrace);
    kp_perf_event_open.symbol_name = "__arm64_sys_perf_event_open"; kp_perf_event_open.pre_handler = handler_pre_perf_event_open; register_kprobe(&kp_perf_event_open);

    pr_info("[GhostCore V10.12] Zero-Crash State Machine & FPU Injector Online.\n"); return 0;
}

void ghost_core_exit_engine(void)
{
    struct hwbp_thread_node *node, *ntmp; struct hwbp_target *tgt, *ttmp;
    LIST_HEAD(local_hwbp); LIST_HEAD(local_target);

    if (kp_wake_up_new_task.addr) unregister_kprobe(&kp_wake_up_new_task);
    if (kp_do_exit.addr) unregister_kprobe(&kp_do_exit);
    if (kp_ptrace.addr) unregister_kprobe(&kp_ptrace);
    if (kp_perf_event_open.addr) unregister_kprobe(&kp_perf_event_open);

    flush_scheduled_work(); msleep(200); 
    spin_lock_bh(&hwbp_thread_lock); list_splice_init(&hwbp_thread_list, &local_hwbp); spin_unlock_bh(&hwbp_thread_lock);
    spin_lock_bh(&hwbp_target_lock); list_splice_init(&hwbp_target_list, &local_target); spin_unlock_bh(&hwbp_target_lock);
    synchronize_rcu();

    list_for_each_entry_safe(node, ntmp, &local_hwbp, list) {
        if (node->bp_event && p_unregister_hwbp) { perf_event_disable(node->bp_event); p_unregister_hwbp(node->bp_event); }
        kfree(node);
    }
    list_for_each_entry_safe(tgt, ttmp, &local_target, list) { kfree(tgt); }
    mempool_destroy(hwbp_elastic_pool); kmem_cache_destroy(hwbp_elastic_cache);
}

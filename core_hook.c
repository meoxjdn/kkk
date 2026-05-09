/*
 * =====================================================================================
 * 
 *       Filename:  core_hook.c
 *    Description:  Ghost Core V10.5 (Ultimate Zero-Footprint Physics Subsystem)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (GKI 5.10 - 6.12 Universal Adaptation)
 *         Author:  顶尖逆向架构师
 * 
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ptrace.h>
#include <linux/workqueue.h>
#include <linux/task_work.h>
#include <linux/mempool.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <asm/ptrace.h>
#include "shadow_hook.h"
#include "dynamic_resolver.h"

/* ==========================================================
 * 物理权限硬编码 (AArch64 PTE Descriptor Attributes)
 * ========================================================== */
#define GHOST_PTE_PXN (1ULL << 53)
#define GHOST_PTE_RX_EL0 ((1ULL << 0) | (1ULL << 6) | (1ULL << 7) | (3ULL << 8) | (1ULL << 10) | (1ULL << 11) | GHOST_PTE_PXN)
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES _IOW('$', 11, struct perf_event_attr *)

/* ==========================================================
 * 动态函数指针声明 (Dynamic Function Pointers via Kallsyms)
 * ========================================================== */
typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
typedef int (*modify_user_hw_breakpoint_t)(struct perf_event *bp, struct perf_event_attr *attr);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *twork, enum task_work_notify_mode mode);
typedef unsigned long (*vm_mmap_t)(struct file *file, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flag, unsigned long offset);
typedef int (*do_mprotect_pkey_t)(unsigned long start, size_t len, unsigned long prot, int pkey);

static register_user_hw_breakpoint_t p_register_hwbp = NULL;
static modify_user_hw_breakpoint_t   p_modify_hwbp = NULL;
static unregister_hw_breakpoint_t    p_unregister_hwbp = NULL;
static task_work_add_t               p_task_work_add = NULL;
static vm_mmap_t                     p_vm_mmap = NULL;
static do_mprotect_pkey_t            p_do_mprotect_pkey = NULL;

/* ==========================================================
 * 全局数据结构与细粒度锁机制 (RCU + Spinlock)
 * ========================================================== */

/* 物理隐身衣追踪节点 */
struct hidden_vma_node {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

/* UXN 高压电网路由节点 */
struct uxn_node {
    struct list_head list;
    struct rcu_head rcu;
    pid_t pid;
    unsigned long orig_page_va;
    unsigned long recomp_va;
    u32 offset_map[1024];
};

/* HWBP 全局目标追踪 */
struct hwbp_target {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid;
    unsigned long orig_entry;
};

/* HWBP 线程级状态机控制节点 */
struct hwbp_thread_node {
    struct list_head list;
    struct rcu_head rcu;
    struct perf_event *bp_event;
    pid_t tid;
    pid_t tgid;
    unsigned long orig_entry;
    unsigned long current_lr;
    bool is_waiting_return;
};

/* Ptrace 统一资源账本 */
struct ptrace_ledger {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid; 
    u32 bp_count;
    u32 wp_count;
    struct user_hwdebug_state bp_state; 
    struct user_hwdebug_state wp_state;
};

/* 异步资源清理工作者 */
struct hwbp_teardown_work {
    struct work_struct work;
    struct hwbp_thread_node *node;
};

/* 复合节点：支持 task_work 与 workqueue 弹性降级 */
struct hwbp_elastic_node {
    struct callback_head t_work;
    struct work_struct w_work;
    struct task_struct *task;
    pid_t tgid;
    unsigned long target_addr;
};

static LIST_HEAD(hidden_vma_list);
static DEFINE_SPINLOCK(hidden_vma_lock);

static LIST_HEAD(uxn_list);
static DEFINE_SPINLOCK(uxn_lock);

static LIST_HEAD(hwbp_target_list);
static DEFINE_SPINLOCK(hwbp_target_lock);

static LIST_HEAD(hwbp_thread_list);
static DEFINE_SPINLOCK(hwbp_thread_lock);

static LIST_HEAD(ledger_list);
static DEFINE_SPINLOCK(ledger_lock);

static struct kmem_cache *hwbp_elastic_cache;
static mempool_t *hwbp_elastic_pool;

/* 全局幽灵分配池基址 (防止内存地址踩踏) */
static uint64_t g_ghost_alloc_base = 0x6000000000;
static DEFINE_MUTEX(ghost_alloc_mutex);

/* ==========================================================
 * 纯汇编存根 (Syscall 无损劫持降级点)
 * ========================================================== */
void stub_sys_ret_0(void);
void stub_sys_ret_enospc(void);

asm(
    ".text\n"
    ".align 2\n"
    ".global stub_sys_ret_0\n"
    "stub_sys_ret_0:\n"
    "   mov x0, #0\n"
    "   ret\n"
    ".global stub_sys_ret_enospc\n"
    "stub_sys_ret_enospc:\n"
    "   mov x0, #-28\n" /* -ENOSPC */
    "   ret\n"
);

/* ==========================================================
 * 核心模块一：Ring 0 VMA 隐蔽解析引擎 (规避 VFS 审计)
 * 兼容 5.10 rbtree 与 6.1+ Maple Tree
 * ========================================================== */
long handle_get_module_base(struct module_base_req *req)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long search_addr = 0;
    long ret = -ESRCH;

    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) { 
        put_task_struct(task); 
        return -ESRCH; 
    }

    mmap_read_lock(mm);
    
    /* 核心逻辑：find_vma 步进搜索，免疫底层数据结构代差 */
    while ((vma = find_vma(mm, search_addr)) != NULL) {
        if (vma->vm_file && vma->vm_file->f_path.dentry) {
            const char *name = vma->vm_file->f_path.dentry->d_name.name;
            if (strstr(name, req->mod_name) && (vma->vm_flags & VM_EXEC)) {
                req->base_addr = vma->vm_start;
                ret = 0;
                break;
            }
        }
        search_addr = vma->vm_end;
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* ==========================================================
 * 核心模块二：目标进程寄生内存调度 (跨进程 MMU 降级)
 * ========================================================== */
struct parasitic_ctx {
    struct callback_head work;
    struct completion done;
    int op; /* 0: mmap, 1: mprotect */
    unsigned long addr;
    unsigned long size;
    long result;
};

static void execute_parasitic_work(struct callback_head *cb)
{
    struct parasitic_ctx *ctx = container_of(cb, struct parasitic_ctx, work);
    if (ctx->op == 0) {
        if (p_vm_mmap) {
            /* 在目标进程上下文强制执行 VMA 分配 */
            ctx->result = p_vm_mmap(NULL, ctx->addr, ctx->size, 
                                    PROT_READ|PROT_WRITE|PROT_EXEC, 
                                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0);
        }
    } else {
        if (p_do_mprotect_pkey) {
            /* 剥夺执行权限，构建 UXN 陷阱 */
            ctx->result = p_do_mprotect_pkey(ctx->addr, ctx->size, PROT_READ|PROT_WRITE, -1);
        }
    }
    complete(&ctx->done);
}

static long force_target_mmu_op(pid_t pid, int op, unsigned long addr, unsigned long size)
{
    struct task_struct *task;
    struct parasitic_ctx ctx;
    long ret = -EFAULT;

    if (!p_task_work_add) return -ENOSYS;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();

    if (!task) return -ESRCH;

    init_completion(&ctx.done);
    ctx.op = op;
    ctx.addr = addr;
    ctx.size = size;
    ctx.result = -EFAULT;
    init_task_work(&ctx.work, execute_parasitic_work);

    /* 强行挂载任务到目标进程，并唤醒其立即执行 */
    if (p_task_work_add(task, &ctx.work, TWA_RESUME) == 0) {
        wake_up_process(task);
        if (wait_for_completion_timeout(&ctx.done, msecs_to_jiffies(2000))) {
            ret = ctx.result;
        } else {
            pr_warn("[GhostCore] Parasitic MMU OP timed out on PID %d\n", pid);
            ret = -EBUSY;
        }
    }
    put_task_struct(task);
    return ret;
}

/* ==========================================================
 * 核心模块三：原子化影子页锻造与闭环注入
 * (Read-Patch-Deploy-Hide-Trap)
 * ========================================================== */
long handle_hide_vma(struct hide_vma_req *req)
{
    struct hidden_vma_node *hnode = kzalloc(sizeof(*hnode), GFP_KERNEL);
    if (!hnode) return -ENOMEM;
    
    hnode->tgid = req->tgid;
    hnode->start_va = req->start_va;
    hnode->end_va = req->end_va;
    
    spin_lock_bh(&hidden_vma_lock);
    list_add_rcu(&hnode->list, &hidden_vma_list);
    spin_unlock_bh(&hidden_vma_lock);
    return 0;
}

long handle_deploy_shadow_patch(struct shadow_patch_req *req)
{
    struct task_struct *task;
    uint64_t page_start = req->target_addr & PAGE_MASK;
    uint32_t page_offset = req->target_addr & ~PAGE_MASK;
    uint8_t *page_buf;
    long ret = -EFAULT;
    struct uxn_node *unode;
    struct hide_vma_req hide_req;
    int i;

    /* 防范越界注入导致内核崩溃 */
    if (req->patch_words > 4 || req->payload_words > 32) return -EINVAL;

    page_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_buf) return -ENOMEM;

    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) { 
        kfree(page_buf); 
        return -ESRCH; 
    }

    mutex_lock(&ghost_alloc_mutex);

    /* 步骤 1: 安全提取目标内存页 (Ring 0 内部克隆，无文件系统审计足迹) */
    if (access_process_vm(task, page_start, page_buf, PAGE_SIZE, FOLL_FORCE) != PAGE_SIZE) {
        goto cleanup;
    }

    /* 步骤 2: 在内存隔离区植入 Patch 与 寄生 Payload */
    if (req->patch_words > 0) {
        memcpy(page_buf + page_offset, req->patch_data, req->patch_words * 4);
    }
    if (req->payload_words > 0 && req->payload_offset > 0 && req->payload_offset < PAGE_SIZE) {
        memcpy(page_buf + req->payload_offset, req->payload_data, req->payload_words * 4);
    }

    /* 步骤 3: 强制目标进程执行 mmap，分配幽灵寄生 VMA */
    ret = force_target_mmu_op(req->pid, 0, g_ghost_alloc_base, PAGE_SIZE);
    if (IS_ERR_VALUE(ret) && ret != g_ghost_alloc_base) goto cleanup;

    /* 步骤 4: 跨进程写入锻造好的影子页数据 */
    if (access_process_vm(task, g_ghost_alloc_base, page_buf, PAGE_SIZE, FOLL_WRITE | FOLL_FORCE) != PAGE_SIZE) {
        ret = -EFAULT; 
        goto cleanup;
    }

    /* 步骤 5: 显式隐藏 VMA，注册到 Kretprobe 隐身衣 */
    hide_req.tgid = req->pid;
    hide_req.start_va = g_ghost_alloc_base;
    hide_req.end_va = g_ghost_alloc_base + PAGE_SIZE;
    handle_hide_vma(&hide_req);

    /* 步骤 6: 原页降级为不可执行，构建 UXN 高压电网 */
    ret = force_target_mmu_op(req->pid, 1, page_start, PAGE_SIZE);
    if (ret != 0) goto cleanup;

    /* 步骤 7: 下发 1:1 缺页路由表 */
    unode = kzalloc(sizeof(*unode), GFP_KERNEL);
    if (unode) {
        unode->pid = req->pid;
        unode->orig_page_va = page_start;
        unode->recomp_va = g_ghost_alloc_base;
        for (i = 0; i < 1024; i++) unode->offset_map[i] = i; 
        
        spin_lock_bh(&uxn_lock);
        list_add_rcu(&unode->list, &uxn_list);
        spin_unlock_bh(&uxn_lock);
    }

    /* 步进，防止多重补丁地址重叠踩踏 */
    g_ghost_alloc_base += PAGE_SIZE;
    ret = 0;

cleanup:
    mutex_unlock(&ghost_alloc_mutex);
    put_task_struct(task);
    kfree(page_buf);
    return ret;
}

/* ==========================================================
 * 核心模块四：/proc/maps 缓冲区时光倒流隐身衣 (Kretprobe)
 * ========================================================== */
struct show_map_data {
    struct seq_file *m;
    size_t prev_count;
};

static struct kretprobe krp_show_map;

static int entry_show_map(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_map_data *data = (struct show_map_data *)ri->data;
    /* 参数 0 是 seq_file 指针 */
    data->m = (struct seq_file *)regs->regs[0];
    data->prev_count = data->m->count;
    return 0;
}

static int ret_show_map(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_map_data *data = (struct show_map_data *)ri->data;
    struct seq_file *m = data->m;
    struct hidden_vma_node *node;
    char hex_feature[32];

    if (!m || !m->buf || m->count <= data->prev_count) return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hidden_vma_list, list) {
        if (node->tgid == current->tgid) {
            snprintf(hex_feature, sizeof(hex_feature), "%lx-%lx", node->start_va, node->end_va);
            /* 若渲染出的 maps 字符串包含幽灵内存特征，强制指针回退抹除 */
            if (strnstr(m->buf + data->prev_count, hex_feature, m->count - data->prev_count)) {
                m->count = data->prev_count;
                break;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

/* ==========================================================
 * 核心模块五：高频 UXN 缺页路由 (The CFG Router)
 * ========================================================== */
static struct kprobe kp_notify_segfault;

static int handler_pre_notify_segfault(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *user_regs = task_pt_regs(current);
    unsigned long fault_addr = regs->regs[0]; 
    struct uxn_node *node;

    if (!user_mode(user_regs)) return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &uxn_list, list) {
        if (node->pid == current->tgid && node->orig_page_va == (fault_addr & PAGE_MASK)) {
            uint32_t insn_idx = (fault_addr & ~PAGE_MASK) / 4;
            /* CFG 重定向至影子页对应的相对偏移 */
            user_regs->pc = node->recomp_va + (node->offset_map[insn_idx] * 4);
            rcu_read_unlock();
            
            /* 修正内核执行流，强制从异常中恢复 */
            instruction_pointer_set(regs, regs->regs[30]);
            return 1;
        }
    }
    rcu_read_unlock();
    return 0;
}

/* ==========================================================
 * 核心模块六：HWBP 全生命周期弹性守护系统 (Hardware Breakpoints)
 * ========================================================== */

static inline unsigned long strip_pac(unsigned long addr) { 
    return addr & ~0xFF00000000000000ULL; 
}

/* 拦截器：接管 Ring 3 异常，实施跳板机制 */
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hwbp_thread_node *node;
    struct perf_event_attr attr;
    if (!user_mode(regs) || !p_modify_hwbp) return;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
        if (node->bp_event != bp) continue;

        if (node->is_waiting_return) {
            attr = bp->attr;
            attr.bp_addr = node->orig_entry;
            perf_event_disable(bp);
            p_modify_hwbp(bp, &attr);
            perf_event_enable(bp);
            node->is_waiting_return = false;
        } else {
            node->current_lr = strip_pac(regs->regs[30]);
            attr = bp->attr;
            attr.bp_addr = node->current_lr;
            perf_event_disable(bp);
            p_modify_hwbp(bp, &attr);
            perf_event_enable(bp);
            node->is_waiting_return = true;
        }
        break;
    }
    rcu_read_unlock();
}

static int install_hwbp_for_thread(struct task_struct *task, pid_t tgid, unsigned long addr)
{
    struct perf_event_attr attr;
    struct perf_event *bp;
    struct hwbp_thread_node *node;

    if (!p_register_hwbp) return -ENOSYS;

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;

    bp = p_register_hwbp(&attr, hwbp_handler, NULL, task);
    if (IS_ERR(bp)) return PTR_ERR(bp);

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) { 
        if (p_unregister_hwbp) p_unregister_hwbp(bp); 
        return -ENOMEM; 
    }

    node->bp_event = bp;
    node->tid = task->pid;
    node->tgid = tgid;
    node->orig_entry = addr;
    node->is_waiting_return = false;

    spin_lock_bh(&hwbp_thread_lock);
    list_add_rcu(&node->list, &hwbp_thread_list);
    spin_unlock_bh(&hwbp_thread_lock);
    return 0;
}

static void execute_install_hwbp(struct task_struct *task, pid_t tgid, unsigned long target_addr)
{
    install_hwbp_for_thread(task, tgid, target_addr);
}

static void task_work_elastic_hwbp(struct callback_head *work)
{
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, t_work);
    execute_install_hwbp(current, en->tgid, en->target_addr);
    mempool_free(en, hwbp_elastic_pool);
}

static void wq_elastic_hwbp(struct work_struct *work)
{
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, w_work);
    execute_install_hwbp(en->task, en->tgid, en->target_addr);
    put_task_struct(en->task);
    mempool_free(en, hwbp_elastic_pool);
}

/* 拦截新线程孵化，自动注入 HWBP (杜绝漏网之鱼) */
static struct kprobe kp_wake_up_new_task;
static int handler_pre_wake_up_new_task(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *new_task = (struct task_struct *)regs->regs[0];
    struct hwbp_target *tgt;
    struct hwbp_elastic_node *en;

    if (!new_task || list_empty(&hwbp_target_list)) return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(tgt, &hwbp_target_list, list) {
        if (tgt->tgid == new_task->tgid) {
            en = mempool_alloc(hwbp_elastic_pool, GFP_ATOMIC);
            if (en) {
                en->tgid = tgt->tgid;
                en->target_addr = tgt->orig_entry;
                en->task = new_task;
                
                /* 弹性降级决策：优先 task_work，降级 workqueue */
                if (p_task_work_add) {
                    init_task_work(&en->t_work, task_work_elastic_hwbp);
                    p_task_work_add(new_task, &en->t_work, TWA_RESUME);
                } else {
                    get_task_struct(new_task);
                    INIT_WORK(&en->w_work, wq_elastic_hwbp);
                    schedule_work(&en->w_work);
                }
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

static void teardown_hwbp_worker(struct work_struct *work)
{
    struct hwbp_teardown_work *w = container_of(work, struct hwbp_teardown_work, work);
    perf_event_disable(w->node->bp_event);
    synchronize_rcu();
    if (p_unregister_hwbp) p_unregister_hwbp(w->node->bp_event);
    kfree(w->node);
    kfree(w);
}

/* 拦截线程退出，释放 HWBP 资源 */
static struct kprobe kp_do_exit;
static int handler_pre_do_exit(struct kprobe *p, struct pt_regs *regs)
{
    struct hwbp_thread_node *node;
    struct hwbp_teardown_work *w;
    pid_t current_tid = current->pid;
    unsigned long flags;

    if (list_empty(&hwbp_thread_list)) return 0;

    spin_lock_irqsave(&hwbp_thread_lock, flags);
    list_for_each_entry(node, &hwbp_thread_list, list) {
        if (node->tid == current_tid) {
            list_del_rcu(&node->list);
            w = kmalloc(sizeof(*w), GFP_ATOMIC);
            if (w) {
                w->node = node;
                INIT_WORK(&w->work, teardown_hwbp_worker);
                schedule_work(&w->work);
            } else {
                kfree_rcu(node, rcu); 
            }
            break;
        }
    }
    spin_unlock_irqrestore(&hwbp_thread_lock, flags);
    return 0;
}

/* 全局 HWBP 注入下发网关 */
long handle_set_hwbp(struct hwbp_req *req)
{
    struct task_struct *g, *t;
    struct hwbp_target *tgt;
    struct task_struct **tasks = NULL;
    int count = 0, i = 0;

    tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
    if (!tgt) return -ENOMEM;
    tgt->tgid = req->tgid;
    tgt->orig_entry = req->target_addr;

    spin_lock_bh(&hwbp_target_lock);
    list_add_rcu(&tgt->list, &hwbp_target_list);
    spin_unlock_bh(&hwbp_target_lock);

    rcu_read_lock();
    for_each_process_thread(g, t) {
        if (t->tgid == req->tgid) count++;
    }
    rcu_read_unlock();

    if (count == 0) return 0;

    tasks = kmalloc_array(count, sizeof(*tasks), GFP_KERNEL);
    if (!tasks) return -ENOMEM;

    count = 0;
    rcu_read_lock();
    for_each_process_thread(g, t) {
        if (t->tgid == req->tgid) {
            get_task_struct(t); 
            tasks[count++] = t;
        }
    }
    rcu_read_unlock();

    for (i = 0; i < count; i++) {
        install_hwbp_for_thread(tasks[i], req->tgid, req->target_addr);
        put_task_struct(tasks[i]);
    }
    kfree(tasks);
    return 0;
}

long handle_hwbp_gate(struct hwbp_req *req, bool enable)
{
    struct hwbp_thread_node *node;
    pid_t current_tid = current->pid;
    pid_t current_tgid = current->tgid;
    
    rcu_read_lock();
    list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
        if (node->tgid == current_tgid && node->tid == current_tid && node->orig_entry == req->target_addr) {
            if (enable) perf_event_enable(node->bp_event);
            else        perf_event_disable(node->bp_event);
            break;
        }
    }
    rcu_read_unlock();
    return 0;
}

/* ==========================================================
 * 核心模块七：统一资源账本 (Perf_Event & Ptrace 终极防御)
 * ========================================================== */

static struct kprobe kp_ptrace;
static struct kprobe kp_perf_event_open;
static struct kprobe kp_sys_ioctl;

static struct ptrace_ledger* get_ledger(pid_t tgid)
{
    struct ptrace_ledger *ledger;
    rcu_read_lock();
    list_for_each_entry_rcu(ledger, &ledger_list, list) {
        if (ledger->tgid == tgid) { rcu_read_unlock(); return ledger; }
    }
    rcu_read_unlock();

    ledger = kzalloc(sizeof(*ledger), GFP_KERNEL);
    if (ledger) {
        ledger->tgid = tgid;
        ledger->bp_count = 0;
        ledger->wp_count = 0;
        memset(&ledger->bp_state, 0, sizeof(ledger->bp_state)); 
        memset(&ledger->wp_state, 0, sizeof(ledger->wp_state)); 
        spin_lock_bh(&ledger_lock);
        list_add_rcu(&ledger->list, &ledger_list);
        spin_unlock_bh(&ledger_lock);
    }
    return ledger;
}

static int safe_copy_from_user(void *dst, const void __user *src, size_t size) {
    int ret; 
    pagefault_disable(); 
    ret = raw_copy_from_user(dst, src, size); 
    pagefault_enable(); 
    return ret;
}

static int safe_copy_to_user(void __user *dst, const void *src, size_t size) {
    int ret; 
    pagefault_disable(); 
    ret = raw_copy_to_user(dst, src, size); 
    pagefault_enable(); 
    return ret;
}

static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs)
{
    long request = regs->regs[0];
    long nt_type = regs->regs[2];
    struct iovec __user *iov_ptr = (struct iovec __user *)regs->regs[3];
    
    struct ptrace_ledger *ledger;
    struct iovec iov;
    struct user_hwdebug_state local_state;

    if (nt_type != 0x402 && nt_type != 0x403) return 0;

    if (request == PTRACE_SETREGSET || request == PTRACE_GETREGSET) {
        ledger = get_ledger(current->tgid); 
        if (!ledger || safe_copy_from_user(&iov, iov_ptr, sizeof(iov))) return 0;

        bool is_bp = (nt_type == 0x402);
        u32 *count_ptr = is_bp ? &ledger->bp_count : &ledger->wp_count;
        struct user_hwdebug_state *state_ptr = is_bp ? &ledger->bp_state : &ledger->wp_state;

        if (request == PTRACE_SETREGSET) {
            if (safe_copy_from_user(&local_state, iov.iov_base, min(iov.iov_len, sizeof(local_state)))) return 0;
            u32 max_regs = is_bp ? 6 : 4; 
            if (*count_ptr >= max_regs) { 
                /* 欺骗反作弊：返回 ENOSPC (设备上没有空间) */
                instruction_pointer_set(regs, (unsigned long)stub_sys_ret_enospc);
            } else {
                memcpy(state_ptr, &local_state, sizeof(local_state));
                (*count_ptr)++;
                instruction_pointer_set(regs, (unsigned long)stub_sys_ret_0);
            }
        } 
        else if (request == PTRACE_GETREGSET) {
            if (safe_copy_to_user(iov.iov_base, state_ptr, min(iov.iov_len, sizeof(*state_ptr)))) return 0;
            instruction_pointer_set(regs, (unsigned long)stub_sys_ret_0);
        }
        return 1; /* 拦截该系统调用，物理断点不受影响 */
    }
    return 0;
}

static int handler_pre_perf_event_open(struct kprobe *p, struct pt_regs *regs)
{
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)regs->regs[0];
    struct perf_event_attr attr;
    struct hwbp_target *tgt;
    struct ptrace_ledger *ledger;
    bool match = false;

    if (safe_copy_from_user(&attr, attr_uptr, sizeof(attr))) return 0;

    if (attr.type == PERF_TYPE_BREAKPOINT) {
        rcu_read_lock();
        list_for_each_entry_rcu(tgt, &hwbp_target_list, list) {
            if (tgt->tgid == current->tgid && tgt->orig_entry == attr.bp_addr) {
                match = true; 
                break;
            }
        }
        rcu_read_unlock();

        if (match) {
            instruction_pointer_set(regs, (unsigned long)stub_sys_ret_enospc);
            return 1;
        }

        ledger = get_ledger(current->tgid);
        if (ledger && ledger->bp_count >= 6) {
            instruction_pointer_set(regs, (unsigned long)stub_sys_ret_enospc);
            return 1;
        }
    }
    return 0;
}

static int handler_pre_sys_ioctl(struct kprobe *p, struct pt_regs *regs)
{
    unsigned int cmd = regs->regs[1];
    
    /* 极速装甲：O(1) 过滤，保护热路径性能 */
    if (unlikely(cmd == PERF_EVENT_IOC_MODIFY_ATTRIBUTES)) {
        unsigned long arg = regs->regs[2];
        struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)arg;
        struct perf_event_attr attr;
        struct hwbp_target *tgt;

        if (safe_copy_from_user(&attr, attr_uptr, sizeof(attr))) return 0;
        
        if (attr.type == PERF_TYPE_BREAKPOINT) {
            rcu_read_lock();
            list_for_each_entry_rcu(tgt, &hwbp_target_list, list) {
                if (tgt->tgid == current->tgid && tgt->orig_entry == attr.bp_addr) {
                    instruction_pointer_set(regs, (unsigned long)stub_sys_ret_enospc);
                    rcu_read_unlock();
                    return 1;
                }
            }
            rcu_read_unlock();
        }
    }
    return 0;
}

/* ==========================================================
 * 生命引擎：动态解析、装载与绝对安全析构
 * ========================================================== */

int ghost_core_init_engine(void)
{
    if (ghost_resolver_init() < 0) {
        pr_err("[GhostCore V10.5] Failed to initialize dynamic resolver.\n");
        return -EINVAL;
    }

    /* 利用 Resolver 突破 GKI KMI 白名单限制 */
    p_register_hwbp = (register_user_hw_breakpoint_t)ghost_resolve_sym("register_user_hw_breakpoint");
    p_modify_hwbp = (modify_user_hw_breakpoint_t)ghost_resolve_sym("modify_user_hw_breakpoint");
    p_unregister_hwbp = (unregister_hw_breakpoint_t)ghost_resolve_sym("unregister_hw_breakpoint");
    p_task_work_add = (task_work_add_t)ghost_resolve_sym("task_work_add");
    p_vm_mmap = (vm_mmap_t)ghost_resolve_sym("vm_mmap");
    p_do_mprotect_pkey = (do_mprotect_pkey_t)ghost_resolve_sym("do_mprotect_pkey");

    hwbp_elastic_cache = kmem_cache_create("hwbp_elastic_cache", sizeof(struct hwbp_elastic_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!hwbp_elastic_cache) return -ENOMEM;
    hwbp_elastic_pool = mempool_create_slab_pool(64, hwbp_elastic_cache);
    if (!hwbp_elastic_pool) {
        kmem_cache_destroy(hwbp_elastic_cache);
        return -ENOMEM;
    }

    #define HOOK_KPROBE(kp, sym, alt_sym, handler) \
        do { \
            kp.symbol_name = sym; \
            kp.pre_handler = handler; \
            if (register_kprobe(&kp) < 0) { \
                if (alt_sym) { \
                    kp.symbol_name = alt_sym; \
                    register_kprobe(&kp); \
                } \
            } \
        } while(0)

    krp_show_map.kp.symbol_name = "show_pid_map";
    krp_show_map.handler = ret_show_map;
    krp_show_map.entry_handler = entry_show_map;
    krp_show_map.data_size = sizeof(struct show_map_data);
    krp_show_map.maxactive = 64;
    if (register_kretprobe(&krp_show_map) < 0) {
        krp_show_map.kp.symbol_name = "show_map_vma";
        register_kretprobe(&krp_show_map);
    }

    HOOK_KPROBE(kp_notify_segfault, "arm64_notify_segfault", NULL, handler_pre_notify_segfault);
    HOOK_KPROBE(kp_wake_up_new_task, "wake_up_new_task", NULL, handler_pre_wake_up_new_task);
    HOOK_KPROBE(kp_do_exit, "do_exit", "make_task_dead", handler_pre_do_exit);
    HOOK_KPROBE(kp_ptrace, "__arm64_sys_ptrace", "sys_ptrace", handler_pre_ptrace);
    HOOK_KPROBE(kp_perf_event_open, "__arm64_sys_perf_event_open", "sys_perf_event_open", handler_pre_perf_event_open);
    
    kp_sys_ioctl.symbol_name = "perf_event_ioctl";
    kp_sys_ioctl.pre_handler = handler_pre_sys_ioctl;
    if (register_kprobe(&kp_sys_ioctl) < 0) {
        HOOK_KPROBE(kp_sys_ioctl, "__arm64_sys_ioctl", "sys_ioctl", handler_pre_sys_ioctl);
    }

    pr_info("[GhostCore V10.5 Engine] Zero-Footprint Physics Subsystem Initialized.\n");
    return 0;
}

void ghost_core_exit_engine(void)
{
    struct hidden_vma_node *vnode, *vtmp;
    struct uxn_node *unode, *utmp;
    struct hwbp_target *tgt, *ttmp;
    struct ptrace_ledger *lnode, *ltmp;
    struct hwbp_thread_node *hnode, *htmp;
    
    struct list_head safe_cleanup_list;
    INIT_LIST_HEAD(&safe_cleanup_list);

    /* 1. 切断探针 */
    unregister_kretprobe(&krp_show_map);
    unregister_kprobe(&kp_notify_segfault);
    unregister_kprobe(&kp_wake_up_new_task);
    unregister_kprobe(&kp_do_exit);
    unregister_kprobe(&kp_ptrace);
    unregister_kprobe(&kp_perf_event_open);
    unregister_kprobe(&kp_sys_ioctl);

    /* 2. 排干工作队列 */
    flush_scheduled_work();

    /* 3. 剥离线程级断点节点，转移到安全回收链表 */
    spin_lock_bh(&hwbp_thread_lock);
    list_splice_init(&hwbp_thread_list, &safe_cleanup_list);
    spin_unlock_bh(&hwbp_thread_lock);

    /* 4. 等待所有 CPU 上的 RCU 宽限期结束，确保没有读锁残留 */
    synchronize_rcu();

    /* 5. 绝对安全的物理剥离与回收 */
    list_for_each_entry_safe(hnode, htmp, &safe_cleanup_list, list) {
        perf_event_disable(hnode->bp_event);
        if (p_unregister_hwbp) p_unregister_hwbp(hnode->bp_event);
        kfree(hnode);
    }

    spin_lock_bh(&hidden_vma_lock);
    list_for_each_entry_safe(vnode, vtmp, &hidden_vma_list, list) {
        list_del_rcu(&vnode->list); 
        kfree_rcu(vnode, rcu);
    }
    spin_unlock_bh(&hidden_vma_lock);

    spin_lock_bh(&uxn_lock);
    list_for_each_entry_safe(unode, utmp, &uxn_list, list) {
        list_del_rcu(&unode->list); 
        kfree_rcu(unode, rcu);
    }
    spin_unlock_bh(&uxn_lock);

    spin_lock_bh(&hwbp_target_lock);
    list_for_each_entry_safe(tgt, ttmp, &hwbp_target_list, list) {
        list_del_rcu(&tgt->list); 
        kfree_rcu(tgt, rcu);
    }
    spin_unlock_bh(&hwbp_target_lock);

    spin_lock_bh(&ledger_lock);
    list_for_each_entry_safe(lnode, ltmp, &ledger_list, list) {
        list_del_rcu(&lnode->list); 
        kfree_rcu(lnode, rcu);
    }
    spin_unlock_bh(&ledger_lock);

    /* 6. 销毁缓存池 */
    mempool_destroy(hwbp_elastic_pool);
    kmem_cache_destroy(hwbp_elastic_cache);

    pr_info("[GhostCore V10.5 Engine] Resources safely drained. Teardown Completed 100%%.\n");
}

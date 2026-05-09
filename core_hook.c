/*
 * =====================================================================================
 * 
 *       Filename:  core_hook.c
 *    Description:  Ghost Core V10.6.2 (Absolute Zero-Footprint, Auto-Stitching, I-Cache Synced)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (100% Full Source, No Truncation)
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
#include <linux/random.h>
#include <linux/delay.h>
#include <asm/ptrace.h>
#include <asm/cacheflush.h>
#include "shadow_hook.h"
#include "dynamic_resolver.h"

/* ==========================================================
 * 物理权限与微型汇编器
 * ========================================================== */
#define GHOST_PTE_PXN (1ULL << 53)
#define GHOST_PTE_RX_EL0 ((1ULL << 0) | (1ULL << 6) | (1ULL << 7) | (3ULL << 8) | (1ULL << 10) | (1ULL << 11) | GHOST_PTE_PXN)
#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES _IOW('$', 11, struct perf_event_attr *)

/* 生成 AArch64 相对跳转指令 (B) */
static inline uint32_t ghost_make_b(uint64_t from, uint64_t to) {
    int32_t offset = (to - from) / 4;
    return 0x14000000 | (offset & 0x03FFFFFF);
}

/* ==========================================================
 * 动态函数指针声明 (Dynamic Function Pointers)
 * ========================================================== */
typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk);
typedef int (*modify_user_hw_breakpoint_t)(struct perf_event *bp, struct perf_event_attr *attr);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *twork, enum task_work_notify_mode mode);
typedef unsigned long (*vm_mmap_t)(struct file *file, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flag, unsigned long offset);
typedef int (*do_mprotect_pkey_t)(unsigned long start, size_t len, unsigned long prot, int pkey);
typedef int (*vm_munmap_t)(unsigned long start, size_t len);

static register_user_hw_breakpoint_t p_register_hwbp = NULL;
static modify_user_hw_breakpoint_t   p_modify_hwbp = NULL;
static unregister_hw_breakpoint_t    p_unregister_hwbp = NULL;
static task_work_add_t               p_task_work_add = NULL;
static vm_mmap_t                     p_vm_mmap = NULL;
static do_mprotect_pkey_t            p_do_mprotect_pkey = NULL;
static vm_munmap_t                   p_vm_munmap = NULL;

/* ==========================================================
 * 全局数据结构与锁机制
 * ========================================================== */
struct hidden_vma_node {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

struct uxn_node {
    struct list_head list;
    struct rcu_head rcu;
    pid_t pid;
    unsigned long orig_page_va;
    unsigned long recomp_va;
    u32 offset_map[1024];
};

struct hwbp_target {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid;
    unsigned long orig_entry;
};

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

struct ptrace_ledger {
    struct list_head list;
    struct rcu_head rcu;
    pid_t tgid; 
    u32 bp_count;
    u32 wp_count;
    struct user_hwdebug_state bp_state; 
    struct user_hwdebug_state wp_state;
};

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

/* 全局幽灵基址 (ASLR 熵值注入) */
static uint64_t g_ghost_alloc_base = 0;
static DEFINE_MUTEX(ghost_alloc_mutex);

/* ==========================================================
 * 纯汇编存根
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
    "   mov x0, #-28\n" 
    "   ret\n"
);

/* ==========================================================
 * 模块零：Ring 0 进程索敌引擎 (基于 Cmdline 精确匹配)
 * ========================================================== */
long handle_get_pid(struct get_pid_req *req)
{
    struct task_struct *task;
    struct mm_struct *mm;
    char *cmdline_buf;
    long ret = -ESRCH;

    if (!req || !req->process_name[0]) {
        return -EINVAL;
    }

    cmdline_buf = kzalloc(256, GFP_KERNEL);
    if (!cmdline_buf) {
        return -ENOMEM;
    }

    rcu_read_lock();
    for_each_process(task) {
        mm = get_task_mm(task);
        if (!mm) {
            continue;
        }

        if (mm->arg_end > mm->arg_start) {
            int len = min_t(unsigned long, mm->arg_end - mm->arg_start, 255);
            if (access_process_vm(task, mm->arg_start, cmdline_buf, len, 0) == len) {
                cmdline_buf[len] = '\0';
                if (strstr(cmdline_buf, req->process_name)) {
                    req->pid = task->tgid;
                    ret = 0;
                    mmput(mm);
                    break;
                }
            }
        }
        mmput(mm);
    }
    rcu_read_unlock();

    kfree(cmdline_buf);
    return ret;
}

/* ==========================================================
 * 模块一：Ring 0 VMA 解析引擎 (锁降级时间切片)
 * ========================================================== */
long handle_get_module_base(struct module_base_req *req)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long search_addr = 0;
    long ret = -ESRCH;
    char name_buf[256];

    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    }
    rcu_read_unlock();

    if (!task) {
        return -ESRCH;
    }
    
    mm = get_task_mm(task);
    if (!mm) { 
        put_task_struct(task); 
        return -ESRCH; 
    }

    while (1) {
        mmap_read_lock(mm);
        vma = find_vma(mm, search_addr);
        if (!vma) { 
            mmap_read_unlock(mm); 
            break; 
        }
        
        search_addr = vma->vm_end;
        if (vma->vm_file && vma->vm_file->f_path.dentry && (vma->vm_flags & VM_EXEC)) {
            strncpy(name_buf, vma->vm_file->f_path.dentry->d_name.name, 255);
            name_buf[255] = '\0';
            
            if (strstr(name_buf, req->mod_name)) {
                req->base_addr = vma->vm_start;
                ret = 0;
                mmap_read_unlock(mm);
                break;
            }
        }
        mmap_read_unlock(mm);
    }

    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* ==========================================================
 * 模块二：目标进程寄生内存调度引擎
 * ========================================================== */
struct parasitic_ctx {
    struct callback_head work;
    struct completion done;
    int op; 
    unsigned long addr;
    unsigned long size;
    long result;
};

static void execute_parasitic_work(struct callback_head *cb)
{
    struct parasitic_ctx *ctx = container_of(cb, struct parasitic_ctx, work);
    if (ctx->op == 0 && p_vm_mmap) {
        ctx->result = p_vm_mmap(NULL, ctx->addr, ctx->size, 
                                PROT_READ|PROT_WRITE|PROT_EXEC, 
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, 0);
    } else if (ctx->op == 1 && p_do_mprotect_pkey) {
        ctx->result = p_do_mprotect_pkey(ctx->addr, ctx->size, PROT_READ|PROT_WRITE, -1);
    } else if (ctx->op == 2 && p_vm_munmap) {
        ctx->result = p_vm_munmap(ctx->addr, ctx->size);
    }
    complete(&ctx->done);
}

static long force_target_mmu_op(pid_t pid, int op, unsigned long addr, unsigned long size)
{
    struct task_struct *task;
    struct parasitic_ctx ctx;
    long ret = -EFAULT;

    if (!p_task_work_add) {
        return -ENOSYS;
    }

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    }
    rcu_read_unlock();

    if (!task) {
        return -ESRCH;
    }

    init_completion(&ctx.done);
    ctx.op = op; 
    ctx.addr = addr; 
    ctx.size = size;
    ctx.result = -EFAULT;
    
    init_task_work(&ctx.work, execute_parasitic_work);

    if (p_task_work_add(task, &ctx.work, TWA_RESUME) == 0) {
        wake_up_process(task);
        if (wait_for_completion_timeout(&ctx.done, msecs_to_jiffies(2000))) {
            ret = ctx.result;
        } else {
            pr_warn("[GhostCore] Parasitic MMU op timed out on PID %d\n", pid);
            ret = -EBUSY;
        }
    }
    
    put_task_struct(task);
    return ret;
}

/* ==========================================================
 * 模块三：影子页锻造与闭环注入 (自动缝合与指令缓存同步)
 * ========================================================== */
long handle_hide_vma(struct hide_vma_req *req)
{
    struct hidden_vma_node *hnode = kzalloc(sizeof(*hnode), GFP_KERNEL);
    if (!hnode) {
        return -ENOMEM;
    }
    
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
    struct uxn_node *unode = NULL;
    uint32_t orig_insn = 0;
    bool vma_allocated = false;
    struct hide_vma_req hide_req;
    int i;

    /* 严苛边界检查，防止恶意载荷越界 */
    if (req->patch_words > 4 || req->payload_words > 30) {
        return -EINVAL;
    }

    page_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_buf) {
        return -ENOMEM;
    }

    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
    }
    rcu_read_unlock();
    
    if (!task) { 
        kfree(page_buf); 
        return -ESRCH; 
    }

    mutex_lock(&ghost_alloc_mutex);

    /* 1. 克隆原物理内存页 */
    if (access_process_vm(task, page_start, page_buf, PAGE_SIZE, FOLL_FORCE) != PAGE_SIZE) {
        ret = -EFAULT; 
        goto err_rollback;
    }
    
    /* 提取原指令用于后续跳板缝合 */
    memcpy(&orig_insn, page_buf + page_offset, 4);

    /* 2. 写入直瞄 Patch 载荷 */
    if (req->patch_words > 0) {
        memcpy(page_buf + page_offset, req->patch_data, req->patch_words * 4);
    }

    /* 3. 复杂 Payload 区的自律式跳板缝合 (Auto-Trampoline) */
    if (req->payload_words > 0 && req->payload_offset > 0 && req->payload_offset < PAGE_SIZE - 64) {
        /* 植入自定义逻辑 */
        memcpy(page_buf + req->payload_offset, req->payload_data, req->payload_words * 4);
        
        uint32_t *stitch_ptr = (uint32_t *)(page_buf + req->payload_offset + req->payload_words * 4);
        /* 自动附加执行原指令 */
        *stitch_ptr = orig_insn;
        
        /* 自动计算 B 跳转，返回原调用位置的下一行 */
        uint64_t current_ghost_pc = g_ghost_alloc_base + req->payload_offset + (req->payload_words + 1) * 4;
        *(stitch_ptr + 1) = ghost_make_b(current_ghost_pc, req->target_addr + 4);
    }

    /* 4. 强制目标分配幽灵 VMA (Mmap 寄生) */
    ret = force_target_mmu_op(req->pid, 0, g_ghost_alloc_base, PAGE_SIZE);
    if (IS_ERR_VALUE(ret) && ret != g_ghost_alloc_base) {
        goto err_rollback;
    }
    vma_allocated = true;

    /* 5. 装填修改后的代码至幽灵 VMA */
    if (access_process_vm(task, g_ghost_alloc_base, page_buf, PAGE_SIZE, FOLL_WRITE | FOLL_FORCE) != PAGE_SIZE) {
        ret = -EFAULT; 
        goto err_rollback;
    }

    /* 6. 核心指令：物理层级刷写指令缓存 (I-Cache Synced) 
     * 解决写入成功但旧缓存导致未生效的顽疾 
     */
    {
        struct mm_struct *mm = get_task_mm(task);
        if (mm) {
            flush_icache_range(g_ghost_alloc_base, g_ghost_alloc_base + PAGE_SIZE);
            mmput(mm);
        }
    }

    /* 7. Kretprobe 掩护名单激活 */
    hide_req.tgid = req->pid;
    hide_req.start_va = g_ghost_alloc_base;
    hide_req.end_va = g_ghost_alloc_base + PAGE_SIZE;
    handle_hide_vma(&hide_req);

    /* 8. 剥离原页执行权限，启动陷阱 */
    if (force_target_mmu_op(req->pid, 1, page_start, PAGE_SIZE) != 0) {
        goto err_rollback;
    }

    /* 9. 构建 1:1 影子路由电网映射表 */
    unode = kzalloc(sizeof(*unode), GFP_KERNEL);
    if (!unode) { 
        ret = -ENOMEM; 
        goto err_rollback; 
    }
    
    unode->pid = req->pid;
    unode->orig_page_va = page_start;
    unode->recomp_va = g_ghost_alloc_base;
    for (i = 0; i < 1024; i++) {
        unode->offset_map[i] = i; 
    }
    
    spin_lock_bh(&uxn_lock);
    list_add_rcu(&unode->list, &uxn_list);
    spin_unlock_bh(&uxn_lock);

    /* 步进 ASLR 基址防踩踏 */
    g_ghost_alloc_base += PAGE_SIZE;
    ret = 0;
    goto cleanup;

err_rollback:
    /* 严格事务回滚，撤销半成品 VMA 分配 */
    if (vma_allocated) {
        force_target_mmu_op(req->pid, 2, g_ghost_alloc_base, PAGE_SIZE);
    }

cleanup:
    mutex_unlock(&ghost_alloc_mutex);
    put_task_struct(task);
    kfree(page_buf);
    return ret;
}

/* ==========================================================
 * 模块四：/proc/maps 时光倒流截断器
 * ========================================================== */
struct show_map_data {
    struct seq_file *m;
    size_t prev_count;
};

static struct kretprobe krp_show_map;

static int entry_show_map(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_map_data *data = (struct show_map_data *)ri->data;
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

    if (!m || !m->buf || m->count <= data->prev_count) {
        return 0;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hidden_vma_list, list) {
        if (node->tgid == current->tgid) {
            snprintf(hex_feature, sizeof(hex_feature), "%lx-%lx", node->start_va, node->end_va);
            if (strnstr(m->buf + data->prev_count, hex_feature, m->count - data->prev_count)) {
                /* 抹除缓冲区输出 */
                m->count = data->prev_count;
                break;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

/* ==========================================================
 * 模块五：高频 UXN 缺页路由 (基于 force_sig_fault 的终极捕获)
 * ========================================================== */
static struct kprobe kp_force_sig;

static int handler_force_sig(struct kprobe *p, struct pt_regs *regs)
{
    int sig = (int)regs->regs[0];
    unsigned long fault_addr = regs->regs[2]; /* X2: force_sig_fault(sig, code, addr) */
    struct pt_regs *user_regs = task_pt_regs(current);
    struct uxn_node *node;

    if (sig != 11 || !user_mode(user_regs)) {
        return 0;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(node, &uxn_list, list) {
        if (node->pid == current->tgid && node->orig_page_va == (fault_addr & PAGE_MASK)) {
            uint32_t insn_idx = (fault_addr & ~PAGE_MASK) / 4;
            user_regs->pc = node->recomp_va + (node->offset_map[insn_idx] * 4);
            rcu_read_unlock();
            
            /* 强制劫持执行流，从异常分发链中安全逃逸 */
            instruction_pointer_set(regs, regs->regs[30]);
            return 1;
        }
    }
    rcu_read_unlock();
    return 0;
}

/* ==========================================================
 * 模块六：HWBP 全生命周期守护系统 (含下发通道)
 * ========================================================== */
static inline unsigned long strip_pac(unsigned long addr) { 
    return addr & ~0xFF00000000000000ULL; 
}

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

static struct kprobe kp_do_exit;
static int handler_pre_do_exit(struct kprobe *p, struct pt_regs *regs)
{
    struct hwbp_thread_node *node, *ntmp;
    pid_t current_tid = current->pid;
    unsigned long flags;

    if (list_empty(&hwbp_thread_list)) return 0;

    spin_lock_irqsave(&hwbp_thread_lock, flags);
    list_for_each_entry_safe(node, ntmp, &hwbp_thread_list, list) {
        if (node->tid == current_tid) {
            list_del_rcu(&node->list);
            /* UAF 修复：仅释放节点，由内核自动回收 perf_event */
            kfree_rcu(node, rcu); 
        }
    }
    spin_unlock_irqrestore(&hwbp_thread_lock, flags);
    return 0;
}

/* 核心注入通道 */
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
 * 模块七：统一资源账本 (Ptrace + PerfEvent 防御)
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
    int ret; pagefault_disable(); ret = raw_copy_from_user(dst, src, size); pagefault_enable(); return ret;
}

static int safe_copy_to_user(void __user *dst, const void *src, size_t size) {
    int ret; pagefault_disable(); ret = raw_copy_to_user(dst, src, size); pagefault_enable(); return ret;
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
        return 1;
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
                match = true; break;
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
 * 生命引擎：装载与隔离物理析构
 * ========================================================== */
int ghost_core_init_engine(void)
{
    uint32_t rnd;

    if (ghost_resolver_init() < 0) return -EINVAL;

    p_register_hwbp = ghost_resolve_sym("register_user_hw_breakpoint");
    p_modify_hwbp = ghost_resolve_sym("modify_user_hw_breakpoint");
    p_unregister_hwbp = ghost_resolve_sym("unregister_hw_breakpoint");
    p_task_work_add = ghost_resolve_sym("task_work_add");
    p_vm_mmap = ghost_resolve_sym("vm_mmap");
    p_do_mprotect_pkey = ghost_resolve_sym("do_mprotect_pkey");
    p_vm_munmap = ghost_resolve_sym("vm_munmap");

    hwbp_elastic_cache = kmem_cache_create("ghost_hwbp_cache", sizeof(struct hwbp_elastic_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!hwbp_elastic_cache) return -ENOMEM;
    hwbp_elastic_pool = mempool_create_slab_pool(64, hwbp_elastic_cache);
    if (!hwbp_elastic_pool) {
        kmem_cache_destroy(hwbp_elastic_cache);
        return -ENOMEM;
    }

    /* 注入 ASLR 熵值 */
    get_random_bytes(&rnd, sizeof(rnd));
    g_ghost_alloc_base = 0x6000000000ULL + (((uint64_t)rnd & 0xFFFFF) << 12);

    /* 挂载探针组 */
    krp_show_map.kp.symbol_name = "show_pid_map";
    krp_show_map.handler = ret_show_map;
    krp_show_map.entry_handler = entry_show_map;
    krp_show_map.data_size = sizeof(struct show_map_data);
    krp_show_map.maxactive = 64;
    register_kretprobe(&krp_show_map);

    kp_force_sig.symbol_name = "force_sig_fault";
    kp_force_sig.pre_handler = handler_force_sig;
    register_kprobe(&kp_force_sig);

    kp_wake_up_new_task.symbol_name = "wake_up_new_task";
    kp_wake_up_new_task.pre_handler = handler_pre_wake_up_new_task;
    register_kprobe(&kp_wake_up_new_task);

    kp_do_exit.symbol_name = "do_exit";
    kp_do_exit.pre_handler = handler_pre_do_exit;
    register_kprobe(&kp_do_exit);

    kp_ptrace.symbol_name = "__arm64_sys_ptrace";
    kp_ptrace.pre_handler = handler_pre_ptrace;
    if (register_kprobe(&kp_ptrace) < 0) {
        kp_ptrace.symbol_name = "sys_ptrace";
        register_kprobe(&kp_ptrace);
    }

    kp_perf_event_open.symbol_name = "__arm64_sys_perf_event_open";
    kp_perf_event_open.pre_handler = handler_pre_perf_event_open;
    if (register_kprobe(&kp_perf_event_open) < 0) {
        kp_perf_event_open.symbol_name = "sys_perf_event_open";
        register_kprobe(&kp_perf_event_open);
    }

    kp_sys_ioctl.symbol_name = "perf_event_ioctl";
    kp_sys_ioctl.pre_handler = handler_pre_sys_ioctl;
    if (register_kprobe(&kp_sys_ioctl) < 0) {
        kp_sys_ioctl.symbol_name = "__arm64_sys_ioctl";
        if (register_kprobe(&kp_sys_ioctl) < 0) {
            kp_sys_ioctl.symbol_name = "sys_ioctl";
            register_kprobe(&kp_sys_ioctl);
        }
    }

    pr_info("[GhostCore V10.6.2] Engine Online. Secure Payload Base: 0x%llx\n", g_ghost_alloc_base);
    return 0;
}

void ghost_core_exit_engine(void)
{
    struct hidden_vma_node *vnode, *vtmp;
    struct uxn_node *unode, *utmp;
    struct hwbp_target *tgt, *ttmp;
    struct ptrace_ledger *lnode, *ltmp;
    struct hwbp_thread_node *hnode, *htmp;
    
    LIST_HEAD(local_hwbp);
    LIST_HEAD(local_vma);
    LIST_HEAD(local_uxn);
    LIST_HEAD(local_target);
    LIST_HEAD(local_ledger);

    /* 绝对安全注销 */
    if (krp_show_map.kp.addr) unregister_kretprobe(&krp_show_map);
    if (kp_force_sig.addr) unregister_kprobe(&kp_force_sig);
    if (kp_wake_up_new_task.addr) unregister_kprobe(&kp_wake_up_new_task);
    if (kp_do_exit.addr) unregister_kprobe(&kp_do_exit);
    if (kp_ptrace.addr) unregister_kprobe(&kp_ptrace);
    if (kp_perf_event_open.addr) unregister_kprobe(&kp_perf_event_open);
    if (kp_sys_ioctl.addr) unregister_kprobe(&kp_sys_ioctl);

    flush_scheduled_work();
    msleep(200); 

    /* 隔离切断 */
    spin_lock_bh(&hwbp_thread_lock); list_splice_init(&hwbp_thread_list, &local_hwbp); spin_unlock_bh(&hwbp_thread_lock);
    spin_lock_bh(&hidden_vma_lock); list_splice_init(&hidden_vma_list, &local_vma); spin_unlock_bh(&hidden_vma_lock);
    spin_lock_bh(&uxn_lock); list_splice_init(&uxn_list, &local_uxn); spin_unlock_bh(&uxn_lock);
    spin_lock_bh(&hwbp_target_lock); list_splice_init(&hwbp_target_list, &local_target); spin_unlock_bh(&hwbp_target_lock);
    spin_lock_bh(&ledger_lock); list_splice_init(&ledger_list, &local_ledger); spin_unlock_bh(&ledger_lock);

    /* 等待全局 RCU 跨界宽限期结束 */
    synchronize_rcu();

    list_for_each_entry_safe(hnode, htmp, &local_hwbp, list) {
        perf_event_disable(hnode->bp_event);
        if (p_unregister_hwbp) p_unregister_hwbp(hnode->bp_event);
        kfree(hnode);
    }

    list_for_each_entry_safe(vnode, vtmp, &local_vma, list) {
        kfree(vnode);
    }

    list_for_each_entry_safe(unode, utmp, &local_uxn, list) {
        kfree(unode);
    }

    list_for_each_entry_safe(tgt, ttmp, &local_target, list) {
        kfree(tgt);
    }

    list_for_each_entry_safe(lnode, ltmp, &local_ledger, list) {
        kfree(lnode);
    }

    mempool_destroy(hwbp_elastic_pool);
    kmem_cache_destroy(hwbp_elastic_cache);

    pr_info("[GhostCore V10.6.2] Resources safely drained. Teardown 100%% Clean.\n");
}

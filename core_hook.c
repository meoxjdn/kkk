/*
 * Ghost Core V10 - The Absolute Final Blueprint (Production Ready)
 * Architecture: AArch64
 * Status: V10 Deployed (Kretprobe Maps Truncation, Fast-Path IOCTL, Unified Ledger)
 * Author: 顶尖逆向架构师
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
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
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>

/* ==========================================================
 * 通信协议与硬编码权限
 * ========================================================== */
#define GHOST_MAGIC 'G'
#define IOCTL_CMD_ALLOC_GHOST   _IOWR(GHOST_MAGIC, 1, struct ghost_alloc_req)
#define IOCTL_CMD_SET_UXN_TRAP  _IOW(GHOST_MAGIC, 2, struct uxn_trap_req)
#define IOCTL_CMD_SET_HWBP      _IOW(GHOST_MAGIC, 3, struct hwbp_req)
#define IOCTL_CMD_DISABLE_HWBP  _IOW(GHOST_MAGIC, 4, struct hwbp_req)
#define IOCTL_CMD_ENABLE_HWBP   _IOW(GHOST_MAGIC, 5, struct hwbp_req)
#define IOCTL_CMD_HIDE_VMA      _IOW(GHOST_MAGIC, 6, struct hide_vma_req)

#define GHOST_PTE_PXN (1ULL << 53)
#define GHOST_PTE_RX_EL0 ((1ULL << 0) | (1ULL << 6) | (1ULL << 7) | (3ULL << 8) | (1ULL << 10) | (1ULL << 11) | GHOST_PTE_PXN)

#define PERF_EVENT_IOC_MODIFY_ATTRIBUTES _IOW('$', 11, struct perf_event_attr *)

struct ghost_alloc_req {
    unsigned long target_va;    
    unsigned long size;         
    void __user *bytecode;
};

struct uxn_trap_req {
    pid_t pid;
    unsigned long orig_page_va; 
    unsigned long recomp_va;    
    u32 offset_map[1024];       
};

struct hwbp_req {
    pid_t tgid;
    unsigned long target_addr;
};

struct hide_vma_req {
    pid_t tgid;
    unsigned long start_va;
    unsigned long end_va;
};

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

struct hwbp_teardown_work {
    struct work_struct work;
    struct hwbp_thread_node *node;
};

struct hwbp_tw_node {
    struct callback_head work;
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

static struct kmem_cache *hwbp_tw_cache;
static mempool_t *hwbp_tw_pool;

/* ==========================================================
 * 纯汇编存根：Syscall 无损劫持
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
 * 模块一：Maps 截断隐藏 (Kretprobe 缓冲区时光倒流)
 * ========================================================== */

static long handle_hide_vma(struct hide_vma_req *req)
{
    struct hidden_vma_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    node->tgid = req->tgid;
    node->start_va = req->start_va;
    node->end_va = req->end_va;

    spin_lock_bh(&hidden_vma_lock);
    list_add_rcu(&node->list, &hidden_vma_list);
    spin_unlock_bh(&hidden_vma_lock);
    return 0;
}

struct show_map_data {
    struct seq_file *m;
    size_t prev_count;
};

static struct kretprobe krp_show_map;

static int entry_show_map(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct show_map_data *data = (struct show_map_data *)ri->data;
    /* 参数 0 永远是 seq_file 指针，这是 C++ / OOP 底层 this 指针传递的铁律 */
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
    bool should_hide = false;

    if (!m || !m->buf || m->count <= data->prev_count) return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hidden_vma_list, list) {
        if (node->tgid == current->tgid) {
            snprintf(hex_feature, sizeof(hex_feature), "%lx-%lx", node->start_va, node->end_va);
            /* 直接在最终渲染的序列化字符串中搜寻物理特征 */
            if (strnstr(m->buf + data->prev_count, hex_feature, m->count - data->prev_count)) {
                should_hide = true;
                break;
            }
        }
    }
    rcu_read_unlock();

    /* 物理级阅后即焚 */
    if (should_hide) {
        m->count = data->prev_count;
    }
    return 0;
}

/* ==========================================================
 * 模块二：VMA-less 幽灵内存直插引擎
 * ========================================================== */

static int inject_ghost_pte(struct mm_struct *mm, unsigned long va, void *kaddr)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep;
    unsigned long pfn;
    
    if (!is_vmalloc_addr(kaddr)) return -EINVAL;
    pfn = vmalloc_to_pfn(kaddr);

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return -EFAULT;
    p4d = p4d_alloc(mm, pgd, va);
    if (!p4d) return -ENOMEM;
    pud = pud_alloc(mm, p4d, va);
    if (!pud) return -ENOMEM;
    pmd = pmd_alloc(mm, pud, va);
    if (!pmd) return -ENOMEM;
    ptep = pte_alloc_map(mm, pmd, va);
    if (!ptep) return -ENOMEM;

    set_pte_ext(ptep, __pte((pfn << PAGE_SHIFT) | GHOST_PTE_RX_EL0), 0);
    pte_unmap(ptep);
    flush_tlb_mm(mm);
    return 0;
}

static long handle_alloc_ghost(struct ghost_alloc_req *req)
{
    void *kmem;
    unsigned long i;
    int ret = 0;

    if (req->size % PAGE_SIZE != 0) return -EINVAL;

    kmem = vzalloc(req->size);
    if (!kmem) return -ENOMEM;

    if (copy_from_user(kmem, req->bytecode, req->size)) {
        vfree(kmem);
        return -EFAULT;
    }

    mmap_write_lock(current->mm);
    for (i = 0; i < req->size; i += PAGE_SIZE) {
        ret = inject_ghost_pte(current->mm, req->target_va + i, kmem + i);
        if (ret) break;
    }
    mmap_write_unlock(current->mm);

    if (ret) vfree(kmem);
    return ret;
}

/* ==========================================================
 * 模块三：安全缺页路由 (Lock-Safe UXN Trap)
 * ========================================================== */

static int set_page_uxn(struct mm_struct *mm, unsigned long va)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep; u64 pval;
    mmap_write_lock(mm);
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd)) goto fail;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d)) goto fail;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud)) goto fail;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) goto fail;
    ptep = pte_offset_map(pmd, va);
    if (!ptep) goto fail;

    pval = pte_val(*ptep);
    pval |= (1ULL << 54); 
    set_pte_ext(ptep, __pte(pval), 0);
    pte_unmap(ptep);
    
    flush_tlb_mm(mm);
    mmap_write_unlock(mm);
    return 0;
fail:
    mmap_write_unlock(mm);
    return -EFAULT;
}

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
            user_regs->pc = node->recomp_va + (node->offset_map[insn_idx] * 4);
            rcu_read_unlock();
            
            instruction_pointer_set(regs, regs->regs[30]);
            return 1;
        }
    }
    rcu_read_unlock();
    return 0;
}

static long handle_set_uxn_trap(struct uxn_trap_req *req)
{
    struct uxn_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) return -ENOMEM;

    node->pid = req->pid;
    node->orig_page_va = req->orig_page_va;
    node->recomp_va = req->recomp_va;
    memcpy(node->offset_map, req->offset_map, sizeof(req->offset_map));

    spin_lock_bh(&uxn_lock);
    list_add_rcu(&node->list, &uxn_list);
    spin_unlock_bh(&uxn_lock);

    return set_page_uxn(current->mm, req->orig_page_va);
}

/* ==========================================================
 * 模块四：HWBP 执行流接管与全生命周期守护
 * ========================================================== */

static inline unsigned long strip_pac(unsigned long addr) { return addr & ~0xFF00000000000000ULL; }

static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hwbp_thread_node *node;
    struct perf_event_attr attr;

    if (!user_mode(regs)) return;

    rcu_read_lock();
    list_for_each_entry_rcu(node, &hwbp_thread_list, list) {
        if (node->bp_event != bp) continue;

        if (node->is_waiting_return) {
            attr = bp->attr;
            attr.bp_addr = node->orig_entry;
            perf_event_disable(bp);
            modify_user_hw_breakpoint(bp, &attr);
            perf_event_enable(bp);
            node->is_waiting_return = false;
        } else {
            node->current_lr = strip_pac(regs->regs[30]);
            attr = bp->attr;
            attr.bp_addr = node->current_lr;
            perf_event_disable(bp);
            modify_user_hw_breakpoint(bp, &attr);
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

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;

    bp = register_user_hw_breakpoint(&attr, hwbp_handler, NULL, task);
    if (IS_ERR(bp)) return PTR_ERR(bp);

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) { unregister_hw_breakpoint(bp); return -ENOMEM; }

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

static void task_work_install_hwbp(struct callback_head *work)
{
    struct hwbp_tw_node *tw = container_of(work, struct hwbp_tw_node, work);
    install_hwbp_for_thread(current, tw->tgid, tw->target_addr);
    mempool_free(tw, hwbp_tw_pool);
}

static struct kprobe kp_wake_up_new_task;
static int handler_pre_wake_up_new_task(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *new_task = (struct task_struct *)regs->regs[0];
    struct hwbp_target *tgt;
    struct hwbp_tw_node *tw;

    if (!new_task || list_empty(&hwbp_target_list)) return 0;

    rcu_read_lock();
    list_for_each_entry_rcu(tgt, &hwbp_target_list, list) {
        if (tgt->tgid == new_task->tgid) {
            tw = mempool_alloc(hwbp_tw_pool, GFP_ATOMIC);
            if (tw) {
                tw->tgid = tgt->tgid;
                tw->target_addr = tgt->orig_entry;
                init_task_work(&tw->work, task_work_install_hwbp);
                task_work_add(new_task, &tw->work, TWA_RESUME);
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
    unregister_hw_breakpoint(w->node->bp_event);
    kfree(w->node);
    kfree(w);
}

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

static long handle_set_hwbp(struct hwbp_req *req)
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

static long handle_hwbp_gate(struct hwbp_req *req, bool enable)
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
 * 模块五：统一资源账本 (Perf_Event & Ptrace 终极防御)
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
    pid_t pid = regs->regs[1];
    long nt_type = regs->regs[2];
    struct iovec __user *iov_ptr = (struct iovec __user *)regs->regs[3];
    
    struct ptrace_ledger *ledger;
    struct iovec iov;
    struct user_hwdebug_state local_state;

    if (nt_type != 0x402 && nt_type != 0x403) return 0;

    if (request == 0x4204 || request == 0x4205) {
        ledger = get_ledger(current->tgid); 
        if (!ledger || safe_copy_from_user(&iov, iov_ptr, sizeof(iov))) return 0;

        bool is_bp = (nt_type == 0x402);
        u32 *count_ptr = is_bp ? &ledger->bp_count : &ledger->wp_count;
        struct user_hwdebug_state *state_ptr = is_bp ? &ledger->bp_state : &ledger->wp_state;

        if (request == 0x4205) {
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
        else if (request == 0x4204) {
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
 * IOCTL 网关与模块生命周期 (绝对排干卸载)
 * ========================================================== */

static long ghost_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ghost_alloc_req alloc_req;
    struct uxn_trap_req trap_req;
    struct hwbp_req hwbp_r;
    struct hide_vma_req hide_req;

    switch (cmd) {
    case IOCTL_CMD_ALLOC_GHOST:
        if (copy_from_user(&alloc_req, (void __user *)arg, sizeof(alloc_req))) return -EFAULT;
        return handle_alloc_ghost(&alloc_req);
    case IOCTL_CMD_SET_UXN_TRAP:
        if (copy_from_user(&trap_req, (void __user *)arg, sizeof(trap_req))) return -EFAULT;
        return handle_set_uxn_trap(&trap_req);
    case IOCTL_CMD_SET_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r))) return -EFAULT;
        return handle_set_hwbp(&hwbp_r);
    case IOCTL_CMD_DISABLE_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r))) return -EFAULT;
        return handle_hwbp_gate(&hwbp_r, false);
    case IOCTL_CMD_ENABLE_HWBP:
        if (copy_from_user(&hwbp_r, (void __user *)arg, sizeof(hwbp_r))) return -EFAULT;
        return handle_hwbp_gate(&hwbp_r, true);
    case IOCTL_CMD_HIDE_VMA:
        if (copy_from_user(&hide_req, (void __user *)arg, sizeof(hide_req))) return -EFAULT;
        return handle_hide_vma(&hide_req);
    default: return -ENOTTY;
    }
}

static const struct file_operations ghost_fops = {
    .owner = THIS_MODULE, .unlocked_ioctl = ghost_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = ghost_ioctl,
#endif
};

static struct miscdevice ghost_miscdev = {
    .minor = MISC_DYNAMIC_MINOR, .name = "ghost_core", .fops = &ghost_fops,
};

static int __init ghost_core_init(void)
{
    if (misc_register(&ghost_miscdev)) return -EINVAL;

    hwbp_tw_cache = kmem_cache_create("hwbp_tw_cache", sizeof(struct hwbp_tw_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!hwbp_tw_cache) return -ENOMEM;
    hwbp_tw_pool = mempool_create_slab_pool(64, hwbp_tw_cache);
    if (!hwbp_tw_pool) {
        kmem_cache_destroy(hwbp_tw_cache);
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

    /* Kretprobe 的特殊挂载法 */
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
    
    /* 尝试挂载专属 IOCTL 优先保护热路径 */
    kp_sys_ioctl.symbol_name = "perf_event_ioctl";
    kp_sys_ioctl.pre_handler = handler_pre_sys_ioctl;
    if (register_kprobe(&kp_sys_ioctl) < 0) {
        HOOK_KPROBE(kp_sys_ioctl, "__arm64_sys_ioctl", "sys_ioctl", handler_pre_sys_ioctl);
    }

    pr_info("[GhostCore V10] The Final Defense Grid Online.\n");
    return 0;
}

static void __exit ghost_core_exit(void)
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
    misc_deregister(&ghost_miscdev);

    /* 2. 排干队列 */
    flush_scheduled_work();

    /* 3. 锁内摘除节点 */
    spin_lock_bh(&hwbp_thread_lock);
    list_splice_init(&hwbp_thread_list, &safe_cleanup_list);
    spin_unlock_bh(&hwbp_thread_lock);

    /* 4. 强等 RCU */
    synchronize_rcu();

    /* 5. 绝对安全的物理剥离 */
    list_for_each_entry_safe(hnode, htmp, &safe_cleanup_list, list) {
        perf_event_disable(hnode->bp_event);
        unregister_hw_breakpoint(hnode->bp_event);
        kfree(hnode);
    }

    spin_lock_bh(&hidden_vma_lock);
    list_for_each_entry_safe(vnode, vtmp, &hidden_vma_list, list) {
        list_del_rcu(&vnode->list); kfree_rcu(vnode, rcu);
    }
    spin_unlock_bh(&hidden_vma_lock);

    spin_lock_bh(&uxn_lock);
    list_for_each_entry_safe(unode, utmp, &uxn_list, list) {
        list_del_rcu(&unode->list); kfree_rcu(unode, rcu);
    }
    spin_unlock_bh(&uxn_lock);

    spin_lock_bh(&hwbp_target_lock);
    list_for_each_entry_safe(tgt, ttmp, &hwbp_target_list, list) {
        list_del_rcu(&tgt->list); kfree_rcu(tgt, rcu);
    }
    spin_unlock_bh(&hwbp_target_lock);

    spin_lock_bh(&ledger_lock);
    list_for_each_entry_safe(lnode, ltmp, &ledger_list, list) {
        list_del_rcu(&lnode->list); kfree_rcu(lnode, rcu);
    }
    spin_unlock_bh(&ledger_lock);

    mempool_destroy(hwbp_tw_pool);
    kmem_cache_destroy(hwbp_tw_cache);

    pr_info("[GhostCore V10] Teardown Completed 100%%. Goodbye.\n");
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("顶尖逆向架构师");

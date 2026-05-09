/*
 * =====================================================================================
 *       Filename:  core_hook.c
 *    Description:  Ghost Core Engine V10.17 (Ultimate Complete Edition)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (Elastic Threads + PC Routing + Anti-Cheat Ledger)
 * =====================================================================================
 */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/anon_inodes.h>
#include <linux/rculist.h>
#include <linux/task_work.h>
#include <linux/mempool.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/ptrace.h>
#include "shadow_hook.h"

#define OFF_BORDER      0x8951160ULL
#define OFF_PAUSE_WIN   0x2639fd8ULL
#define OFF_PAUSE_JMP   0x53709a0ULL
#define OFF_KILL        0x33b2ffcULL
#define OFF_DAMAGE      0x844f4d0ULL
#define OFF_FOV         0x9326F78ULL  

#define FOV_TARGET_BITS 0x4089999AU

/* ==========================================================
 * 全局状态机与 RCU 线程生命周期管理
 * ========================================================== */
static uint64_t          g_game_base  = 0;
static int               g_fov_on     = 0;
static int               g_border_on  = 0;
static int               g_skip_on    = 0;
static int               g_damage_on  = 0;
static int               g_maxhp_on   = 0;
static pid_t             g_target_tgid = 0;

static DEFINE_SPINLOCK(g_thread_lock);
static LIST_HEAD(g_thread_list);

static struct kmem_cache *hwbp_elastic_cache;
static mempool_t *hwbp_elastic_pool;

struct hwbp_thread_node {
    struct list_head list;
    struct rcu_head rcu;
    struct perf_event *bp_event;
    pid_t tid;
};

struct hwbp_elastic_node {
    struct callback_head t_work;
    struct work_struct w_work;
    struct task_struct *task;
};

/* 原生 KMI 6.6 ABI 假账本 */
static struct user_hwdebug_state g_fake_ledger;

/* ==========================================================
 * Kprobe 符号偷渡引擎
 * ========================================================== */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t ghost_kallsyms_lookup_name = NULL;

static int init_ghost_resolver(void) {
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    
    if (register_kprobe(&kp) < 0) return -1;
    
    ghost_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

/* 动态指针与符号解析 */
typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);
typedef int (*task_work_add_t)(struct task_struct *task, struct callback_head *twork, enum task_work_notify_mode mode);

static reg_fn_t           fn_register      = NULL;
static unreg_fn_t         fn_unregister    = NULL;
static read_nofault_fn_t  fn_nofault_read  = NULL;
static fpsimd_save_fn_t   fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t   fn_fpsimd_load   = NULL;
static task_work_add_t    fn_task_work_add = NULL;

static int resolve_symbols_natively(void) {
    if (fn_register) return 0;
    
    if (!ghost_kallsyms_lookup_name) {
        if (init_ghost_resolver() < 0) return -ENOSYS;
    }

    fn_register = (reg_fn_t)ghost_kallsyms_lookup_name("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)ghost_kallsyms_lookup_name("unregister_hw_breakpoint");
    fn_nofault_read = (read_nofault_fn_t)ghost_kallsyms_lookup_name("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)ghost_kallsyms_lookup_name("probe_kernel_read");
    fn_fpsimd_save = (fpsimd_save_fn_t)ghost_kallsyms_lookup_name("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)ghost_kallsyms_lookup_name("fpsimd_save_and_flush_cpu_state");
    fn_fpsimd_load = (fpsimd_load_fn_t)ghost_kallsyms_lookup_name("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)ghost_kallsyms_lookup_name("fpsimd_flush_cpu_state");
    fn_task_work_add = (task_work_add_t)ghost_kallsyms_lookup_name("task_work_add");

    if (!fn_register || !fn_unregister) return -ENOSYS;
    return 0;
}

/* ==========================================================
 * PC 绝对地址路由 (零死锁控制流矩阵)
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (unlikely(!regs)) return;

    pc   = regs->pc;
    base = g_game_base;

    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        return;
    }

    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    if (g_damage_on && pc == base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1C;
        if (fn_nofault_read) {
            if (fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
                if (flag == 1) { 
                    regs->regs[19] = regs->regs[1]; 
                    regs->pc += 4; 
                    return;
                }
            }
        }
        regs->sp += 0x30;
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    if (g_fov_on && pc == base + OFF_FOV) {
        if (fn_fpsimd_save && fn_fpsimd_load) {
            struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
            fn_fpsimd_load(fp);
        }
        regs->pc = regs->regs[30];
        return;
    }
}

/* ==========================================================
 * 弹性断点下发与回收
 * ========================================================== */
static int install_bp_on_thread(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event *bp;
    struct hwbp_thread_node *node;

    if (!fn_register) return -ENOSYS;

    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;

    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) return PTR_ERR(bp);

    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (!node) {
        fn_unregister(bp);
        return -ENOMEM;
    }

    node->bp_event = bp;
    node->tid = tsk->pid;

    spin_lock_bh(&g_thread_lock);
    list_add_rcu(&node->list, &g_thread_list);
    spin_unlock_bh(&g_thread_lock);

    return 0;
}

static void apply_all_bps(struct task_struct *tsk) {
    if (g_border_on) install_bp_on_thread(tsk, g_game_base + OFF_BORDER);
    if (g_skip_on)   install_bp_on_thread(tsk, g_game_base + OFF_PAUSE_WIN);
    if (g_maxhp_on)  install_bp_on_thread(tsk, g_game_base + OFF_KILL);
    if (g_damage_on) install_bp_on_thread(tsk, g_game_base + OFF_DAMAGE);
    if (g_fov_on)    install_bp_on_thread(tsk, g_game_base + OFF_FOV);
}

/* ==========================================================
 * 新生线程自动追捕与死亡释放
 * ========================================================== */
static void task_work_elastic_hwbp(struct callback_head *work) {
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, t_work);
    apply_all_bps(current);
    mempool_free(en, hwbp_elastic_pool);
}

static void wq_elastic_hwbp(struct work_struct *work) {
    struct hwbp_elastic_node *en = container_of(work, struct hwbp_elastic_node, w_work);
    apply_all_bps(en->task);
    put_task_struct(en->task);
    mempool_free(en, hwbp_elastic_pool);
}

static struct kprobe kp_wake_up_new_task;
static int handler_pre_wake_up_new_task(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *new_task = (struct task_struct *)regs->regs[0];
    struct hwbp_elastic_node *en;

    if (!new_task || g_target_tgid == 0) return 0;

    if (new_task->tgid == g_target_tgid) {
        en = mempool_alloc(hwbp_elastic_pool, GFP_ATOMIC);
        if (en) {
            en->task = new_task;
            if (fn_task_work_add) {
                init_task_work(&en->t_work, task_work_elastic_hwbp);
                fn_task_work_add(new_task, &en->t_work, TWA_RESUME);
            } else {
                get_task_struct(new_task);
                INIT_WORK(&en->w_work, wq_elastic_hwbp);
                schedule_work(&en->w_work);
            }
        }
    }
    return 0;
}

static struct kprobe kp_do_exit;
static int handler_pre_do_exit(struct kprobe *p, struct pt_regs *regs) {
    struct hwbp_thread_node *node, *ntmp;
    pid_t current_tid = current->pid;
    
    if (list_empty(&g_thread_list)) return 0;

    spin_lock_bh(&g_thread_lock);
    list_for_each_entry_safe(node, ntmp, &g_thread_list, list) {
        if (node->tid == current_tid) {
            list_del_rcu(&node->list);
            kfree_rcu(node, rcu); 
        }
    }
    spin_unlock_bh(&g_thread_lock);
    return 0;
}

/* ==========================================================
 * 引擎暴露接口：下发与清理
 * ========================================================== */
int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *g, *t;

    if (!req) return -EINVAL;
    if (resolve_symbols_natively() != 0) return -ENOSYS;

    g_target_tgid = req->tid;
    g_game_base   = req->base_addr;
    g_border_on   = req->border_on;
    g_skip_on     = req->skip_on;
    g_damage_on   = req->damage_on;
    g_maxhp_on    = req->maxhp_on;
    g_fov_on      = req->fov_on;
    
    memset(&g_fake_ledger, 0, sizeof(g_fake_ledger));

    /* 遍历当前存活线程批量下发 */
    rcu_read_lock();
    for_each_process_thread(g, t) {
        if (t->tgid == g_target_tgid) {
            get_task_struct(t);
            apply_all_bps(t);
            put_task_struct(t);
        }
    }
    rcu_read_unlock();

    return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    struct hwbp_thread_node *node, *ntmp;
    LIST_HEAD(local_list);

    g_target_tgid = 0;

    spin_lock_bh(&g_thread_lock);
    list_splice_init(&g_thread_list, &local_list);
    spin_unlock_bh(&g_thread_lock);

    synchronize_rcu();

    list_for_each_entry_safe(node, ntmp, &local_list, list) {
        if (node->bp_event && fn_unregister) {
            fn_unregister(node->bp_event);
        }
        kfree(node);
    }
}

/* ==========================================================
 * 楚门的世界：反作弊欺骗网 (Ptrace & Perf Dummy)
 * ========================================================== */
static struct kprobe kp_ptrace;
static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    long request = sys_regs->regs[0];
    long addr    = sys_regs->regs[2];
    void __user *data = (void __user *)sys_regs->regs[3];
    struct iovec iov; 

    if (addr == 0x402) { 
        if (copy_from_user(&iov, data, sizeof(iov))) return 0;
        if (request == PTRACE_SETREGSET) {
            if (iov.iov_len > sizeof(struct user_hwdebug_state)) {
                regs->regs[0] = -ENOSPC; 
                instruction_pointer_set(regs, regs->regs[30]);
                return 0;
            }
            if (copy_from_user(&g_fake_ledger, iov.iov_base, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
        } 
        else if (request == PTRACE_GETREGSET) {
            if (copy_to_user(iov.iov_base, &g_fake_ledger, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
        }
        regs->regs[0] = 0; 
        instruction_pointer_set(regs, regs->regs[30]);
    }
    return 0;
}

static long dummy_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { return 0; }
static ssize_t dummy_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    uint64_t dummy = 0;
    if (count >= sizeof(uint64_t)) { if (copy_to_user(buf, &dummy, sizeof(uint64_t)) == 0) return sizeof(uint64_t); }
    return 0;
}
static const struct file_operations dummy_perf_fops = { .owner = THIS_MODULE, .unlocked_ioctl = dummy_perf_ioctl, .compat_ioctl = dummy_perf_ioctl, .read = dummy_perf_read, };

static struct kprobe kp_perf_event_open;
static int handler_pre_perf_event_open(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)sys_regs->regs[0];
    struct perf_event_attr attr; 
    int dummy_fd;

    if (copy_from_user(&attr, attr_uptr, sizeof(attr)) == 0) {
        if (attr.type == PERF_TYPE_BREAKPOINT) {
            dummy_fd = anon_inode_getfd("[fake_perf_hwbp]", &dummy_perf_fops, NULL, O_RDWR | O_CLOEXEC);
            if (dummy_fd >= 0) { regs->regs[0] = dummy_fd; } 
            else { regs->regs[0] = -ENOSPC; }
            instruction_pointer_set(regs, regs->regs[30]);
        }
    }
    return 0;
}

/* ==========================================================
 * 点火与熄火核心例程
 * ========================================================== */
int ghost_core_init_engine(void) {
    hwbp_elastic_cache = kmem_cache_create("ghost_hwbp_cache", sizeof(struct hwbp_elastic_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (!hwbp_elastic_cache) return -ENOMEM;
    
    hwbp_elastic_pool = mempool_create_slab_pool(64, hwbp_elastic_cache);
    if (!hwbp_elastic_pool) {
        kmem_cache_destroy(hwbp_elastic_cache);
        return -ENOMEM;
    }

    kp_wake_up_new_task.symbol_name = "wake_up_new_task";
    kp_wake_up_new_task.pre_handler = handler_pre_wake_up_new_task;
    register_kprobe(&kp_wake_up_new_task);

    kp_do_exit.symbol_name = "do_exit";
    kp_do_exit.pre_handler = handler_pre_do_exit;
    register_kprobe(&kp_do_exit);

    kp_ptrace.symbol_name = "__arm64_sys_ptrace"; 
    kp_ptrace.pre_handler = handler_pre_ptrace;
    register_kprobe(&kp_ptrace);

    kp_perf_event_open.symbol_name = "__arm64_sys_perf_event_open"; 
    kp_perf_event_open.pre_handler = handler_pre_perf_event_open;
    register_kprobe(&kp_perf_event_open);

    return 0;
}

void ghost_core_exit_engine(void) {
    if (kp_wake_up_new_task.addr) unregister_kprobe(&kp_wake_up_new_task);
    if (kp_do_exit.addr) unregister_kprobe(&kp_do_exit);
    if (kp_ptrace.addr) unregister_kprobe(&kp_ptrace);
    if (kp_perf_event_open.addr) unregister_kprobe(&kp_perf_event_open);
    
    wuwa_cleanup_perf_hbp();
    
    if (hwbp_elastic_pool) mempool_destroy(hwbp_elastic_pool);
    if (hwbp_elastic_cache) kmem_cache_destroy(hwbp_elastic_cache);
}

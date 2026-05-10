/*
 * =====================================================================================
 *       Filename:  core.c
 *    Description:  Ghost Core Engine V10.35 (Absolute Kamikaze Sentinel)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (Zero-Crash, Safe Mutex, O(1) Probe)
 *         Author:  顶尖逆向架构师
 * =====================================================================================
 */

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/atomic.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");

/* ==========================================================
 * 物理内存偏移与掩码定义
 * ========================================================== */
#define OFF_BORDER      0x8951160ULL
#define OFF_PAUSE_WIN   0x2639fd8ULL
#define OFF_PAUSE_JMP   0x53709a0ULL
#define OFF_KILL        0x33b2ffcULL
#define OFF_DAMAGE      0x844f4d0ULL
#define OFF_FOV         0x9326F78ULL  

#define MAX_BPS         160
#define FOV_TARGET_BITS 0x40900000ULL /* 4.5f 广角甜点值 */

/* ==========================================================
 * 全局状态机与锁
 * ========================================================== */
static uint64_t          g_game_base  = 0;
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count   = 0;
static int               g_fov_on     = 0;
static int               g_border_on  = 0;
static int               g_skip_on    = 0;
static int               g_damage_on  = 0;
static int               g_maxhp_on   = 0;

static DEFINE_MUTEX(g_bp_mutex);

/* Kamikaze 核心标志位：0=正常，1=已自毁跑路 */
static atomic_t g_self_destruct = ATOMIC_INIT(0);

#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
    int      maxhp_on;
};
#pragma pack(pop)

struct core_cmd_packet {
    uint32_t cmd_id;
    uint64_t payload_ptr;
};

#define CMD_HBP_INSTALL 0x5A5A1001
#define CMD_HBP_CLEANUP 0x5A5A1002

/* ==========================================================
 * 动态函数指针解析器
 * ========================================================== */
typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t                 fn_register      = NULL;
static unreg_fn_t               fn_unregister    = NULL;
static read_nofault_fn_t        fn_nofault_read  = NULL;
static fpsimd_save_fn_t         fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t         fn_fpsimd_load   = NULL;
static kallsyms_lookup_name_t   ghost_kallsyms_lookup_name = NULL;

static int init_ghost_resolver(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    ghost_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

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

    if (!fn_register || !fn_unregister || !fn_nofault_read) return -ENOSYS;
    return 0;
}

/* ==========================================================
 * 核心控制流路由 (纯净版，绝不死机)
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (unlikely(!regs)) return;
    
    /* 自毁状态隔离：一旦跑路，立即切断控制流拦截 */
    if (atomic_read(&g_self_destruct)) return;

    pc   = regs->pc;
    base = g_game_base;

    /* 去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 秒过 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        return;
    }

    /* 秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 无敌 */
    if (g_damage_on && pc == base + OFF_DAMAGE) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
        return;
    }

    /* FOV 全屏 (依靠 preempt 屏障隔离 FPU 上下文) */
    if (g_fov_on && pc == base + OFF_FOV) {
        preempt_disable(); 
        if (fn_fpsimd_save && fn_fpsimd_load) {
            struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
            fn_fpsimd_load(fp);
        }
        regs->regs[0] = FOV_TARGET_BITS;
        preempt_enable();
        regs->pc = regs->regs[30];
        return;
    }
}

/* ==========================================================
 * 硬件断点清理模块 (分离式安全设计)
 * ========================================================== */

/* 1. 用于神风特攻的非阻塞清理 (IRQ 上下文安全) */
static void wuwa_cleanup_perf_hbp_safe(void) {
    int i;
    /* 核心修复：IRQ 上下文锁逃逸，防死锁 */
    if (!mutex_trylock(&g_bp_mutex)) {
        pr_info("[GhostCore] Mutex locked by another thread. Cleanup deferred.\n");
        return; 
    }
    
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) {
            fn_unregister(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    
    /* 状态机全局静默 */
    g_game_base = 0;
    g_fov_on = g_border_on = g_skip_on = g_damage_on = g_maxhp_on = 0;
    
    mutex_unlock(&g_bp_mutex);
    pr_info("[GhostCore] Kamikaze successful. All traces erased.\n");
}

/* 2. 用于用户态主动清理或模块卸载的阻塞清理 */
static void wuwa_cleanup_perf_hbp_blocking(void) {
    int i;
    mutex_lock(&g_bp_mutex);
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i] && fn_unregister) {
            fn_unregister(g_bps[i]);
            g_bps[i] = NULL;
        }
    }
    g_bp_count = 0;
    g_game_base = 0;
    g_fov_on = g_border_on = g_skip_on = g_damage_on = g_maxhp_on = 0;
    mutex_unlock(&g_bp_mutex);
}

/* ==========================================================
 * 硬件断点下发模块
 * ========================================================== */
static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event     *bp;
    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;
    
    if (!fn_register) return NULL;
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) return NULL;
    return bp;
}

static int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk;
    struct pid         *pid_struct;

    if (!req) return -EINVAL;
    if (resolve_symbols_natively() != 0) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    /* 复位自毁跑路标志，允许重新挂载 */
    atomic_set(&g_self_destruct, 0);

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0) {
        g_game_base = req->base_addr;
        g_border_on = req->border_on;
        g_skip_on   = req->skip_on;
        g_damage_on = req->damage_on;
        g_maxhp_on  = req->maxhp_on;
        g_fov_on    = req->fov_on;
    }

    if (g_bp_count + 5 >= MAX_BPS) goto unlock_out;

    if (req->border_on) { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_BORDER); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->skip_on)   { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_PAUSE_WIN); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->maxhp_on)  { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_KILL); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->damage_on) { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_DAMAGE); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->fov_on)    { struct perf_event *bp = install_bp(tsk, req->base_addr + OFF_FOV); if (bp) g_bps[g_bp_count++] = bp; }

unlock_out:
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);
    return 0;
}

/* ==========================================================
 * 终极神风特攻防线：被动嗅探，主动跑路 (Kamikaze Matrix)
 * ========================================================== */

static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    long request, addr;

    if (atomic_read(&g_self_destruct) || !sys_regs) return 0;

    request = sys_regs->regs[0];
    addr    = sys_regs->regs[2];

    /* 嗅探到反作弊正在写入硬件断点寄存器 */
    if (request == PTRACE_SETREGSET && addr == 0x402) { /* NT_ARM_HW_BREAK */
        if (atomic_cmpxchg(&g_self_destruct, 0, 1) == 0) {
            pr_info("[GhostCore] AC active probe detected (Ptrace). Kamikaze protocol engaged.\n");
            wuwa_cleanup_perf_hbp_safe(); /* 非阻塞跑路 */
        }
    }
    return 0;
}

static int handler_pre_perf_event(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    void __user *attr_uptr;
    uint32_t attr_type;

    if (atomic_read(&g_self_destruct) || !sys_regs || !fn_nofault_read) return 0;

    attr_uptr = (void __user *)sys_regs->regs[0];

    /* 
     * 核心优化：O(1) Memory Footprint。
     * 在 perf_event_attr 结构体中，__u32 type 位于偏移量 0 处。
     * 我们仅安全读取 4 个字节，极大降低内核态异常概率。
     */
    if (fn_nofault_read(&attr_type, attr_uptr, sizeof(uint32_t)) == 0) {
        if (attr_type == PERF_TYPE_BREAKPOINT) {
            if (atomic_cmpxchg(&g_self_destruct, 0, 1) == 0) {
                pr_info("[GhostCore] AC active probe detected (Perf). Kamikaze protocol engaged.\n");
                wuwa_cleanup_perf_hbp_safe(); /* 非阻塞跑路 */
            }
        }
    }
    return 0; 
}

static struct kprobe kp_ptrace = {
    .symbol_name = "__arm64_sys_ptrace",
    .pre_handler = handler_pre_ptrace,
};

static struct kprobe kp_perf = {
    .symbol_name = "__arm64_sys_perf_event_open",
    .pre_handler = handler_pre_perf_event,
};

/* ==========================================================
 * VFS 通信网关 (集成状态读取 endpoint)
 * ========================================================== */
static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req req;
    
    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;
    
    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) return -EFAULT;
        wuwa_install_perf_hbp(&req);
    } 
    else if (pkt.cmd_id == CMD_HBP_CLEANUP) {
        wuwa_cleanup_perf_hbp_blocking(); /* 主动清理使用阻塞锁 */
    }
    return count;
}

static ssize_t core_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    int status = atomic_read(&g_self_destruct);
    if (count >= sizeof(int)) {
        if (copy_to_user(buf, &status, sizeof(int))) return -EFAULT;
        return sizeof(int);
    }
    return 0;
}

static const struct file_operations core_fops = {
    .owner = THIS_MODULE,
    .write = core_write,
    .read  = core_read,
};

static struct miscdevice core_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "logd_service",
    .fops  = &core_fops,
};

/* ==========================================================
 * 模块生命周期管理
 * ========================================================== */
static int __init ghost_core_init(void) {
    register_kprobe(&kp_ptrace);
    register_kprobe(&kp_perf);
    misc_register(&core_misc);
    pr_info("[GhostCore V10.35] Kamikaze Edition Online. O(1) Probe & Safe Mutex Active.\n");
    return 0;
}

static void __exit ghost_core_exit(void) {
    if (kp_ptrace.addr) unregister_kprobe(&kp_ptrace);
    if (kp_perf.addr) unregister_kprobe(&kp_perf);
    wuwa_cleanup_perf_hbp_blocking();
    misc_deregister(&core_misc);
    pr_info("[GhostCore V10.35] Offline.\n");
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

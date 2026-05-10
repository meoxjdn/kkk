/*
 * =====================================================================================
 *       Filename:  core.c
 *    Description:  Ghost Core Engine V10.37 (The Final Precision Payload)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (Stack Unwinding Fixed, FPU Restored, Kretprobe)
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
#include <linux/anon_inodes.h>
#include <linux/module.h>
#include <linux/preempt.h>
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

/* 严格回调至 4.5f，确保广角视觉正常，消灭黑屏 */
#define FOV_TARGET_BITS 0x40900000ULL
#define ARM64_MAX_HW_BPS 6

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

/* 假账本防线：完美的空记录 */
static struct user_hwdebug_state g_fake_ledger;

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
 * 核心控制流路由 (The Precision Payload CFG Router)
 * 完美恢复堆栈平衡与 FPU 上下文写入
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc, base;

    if (unlikely(!regs)) return;
    pc   = regs->pc;
    base = g_game_base;

    /* 1. 决斗场去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 2. 副本秒过 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        return;
    }

    /* 3. 秒杀 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 4. 伤害无敌判定 (修复堆栈不平衡导致的闪退) */
    if (g_damage_on && pc == base + OFF_DAMAGE) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1C;
        
        /* 内存探针判定：安全读取，规避缺页死机 */
        if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
            if (flag == 1) { 
                /* 己方攻击：模拟执行被 Hook 的原始指令，放行不予修改 */
                regs->regs[19] = regs->regs[1]; 
                regs->pc += 4; 
                return;
            }
        }
        
        /* 敌方攻击：修改返回值免除伤害，必须解包极序堆栈补偿 0x30，防止外层函数读取乱码 LR */
        regs->sp += 0x30;
        regs->regs[0] = 0; 
        regs->pc = regs->regs[30];
        return;
    }

    /* 5. 全屏 FOV (修复黑屏：恢复真实的 FPU 物理状态修改) */
    if (g_fov_on && pc == base + OFF_FOV) {
        preempt_disable(); /* 禁用抢占屏障，防止 FPU 状态机漂移 */
        if (fn_fpsimd_save && fn_fpsimd_load) {
            struct user_fpsimd_state *fp = &current->thread.uw.fpsimd_state;
            fn_fpsimd_save(fp);
            /* 安全修改 NEON 寄存器组 S0 */
            fp->vregs[0] = (fp->vregs[0] & ~((__uint128_t)0xFFFFFFFFULL)) | (__uint128_t)FOV_TARGET_BITS;
            fn_fpsimd_load(fp);
        }
        regs->regs[0] = FOV_TARGET_BITS; /* 同步修改通用寄存器兜底 */
        preempt_enable();
        regs->pc = regs->regs[30];
        return;
    }
}

/* ==========================================================
 * 硬件断点分发模块
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

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk;
    struct pid         *pid_struct;

    if (!req) return -EINVAL;
    if (resolve_symbols_natively() != 0) return -ENOSYS;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) return -ESRCH;

    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0) {
        g_game_base = req->base_addr;
        g_border_on = req->border_on;
        g_skip_on   = req->skip_on;
        g_damage_on = req->damage_on;
        g_maxhp_on  = req->maxhp_on;
        g_fov_on    = req->fov_on;
        memset(&g_fake_ledger, 0, sizeof(g_fake_ledger));
    }

    if (g_bp_count + 5 >= MAX_BPS) goto unlock_out;

    pr_info("[GhostCore] Securing Thread %d (Base: 0x%llx)...\n", req->tid, req->base_addr);

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

void wuwa_cleanup_perf_hbp(void) {
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
    mutex_unlock(&g_bp_mutex);
    pr_info("[GhostCore] Anchors detached.\n");
}

/* ==========================================================
 * 反作弊伪装矩阵：Kretprobe 幽灵拦截
 * 包含深度越界对抗与无死锁的上下文分离
 * ========================================================== */

/* 1. Ptrace 幽灵账本 */
struct ptrace_stash {
    long request;
    long addr;
    void __user *data;
    int valid;
};

static int entry_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    
    stash->valid = 0;
    if (!sys_regs) return 0;
    
    stash->request = sys_regs->regs[0];
    stash->addr    = sys_regs->regs[2];
    stash->data    = (void __user *)sys_regs->regs[3];
    stash->valid   = 1;
    return 0; 
}

static int ret_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    struct iovec iov;
    uint32_t req_bps_count;

    if (!stash->valid) return 0;
    
    if (stash->addr == 0x402) { 
        if (copy_from_user(&iov, stash->data, sizeof(iov)) == 0) {
            if (stash->request == PTRACE_SETREGSET) {
                if (iov.iov_len > sizeof(struct user_hwdebug_state)) {
                    regs->regs[0] = -ENOSPC; 
                } else {
                    if (copy_from_user(&g_fake_ledger, iov.iov_base, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
                    
                    /* 深度防越界诱导 */
                    req_bps_count = g_fake_ledger.dbg_info & 0xFF;
                    if (req_bps_count > ARM64_MAX_HW_BPS) {
                        regs->regs[0] = -ENOSPC;
                    } else {
                        regs->regs[0] = 0; 
                    }
                }
            } 
            else if (stash->request == PTRACE_GETREGSET) {
                if (copy_to_user(iov.iov_base, &g_fake_ledger, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {}
                regs->regs[0] = 0; 
            }
        }
    }
    return 0;
}

static struct kretprobe krp_ptrace = {
    .kp.symbol_name = "__arm64_sys_ptrace",
    .entry_handler  = entry_handler_ptrace,
    .handler        = ret_handler_ptrace,
    .data_size      = sizeof(struct ptrace_stash),
    .maxactive      = 32,
};

/* 2. Perf 虚拟空壳 FD */
static long dummy_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { return 0; }
static ssize_t dummy_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    uint64_t dummy = 0;
    if (count >= sizeof(uint64_t)) { 
        if (copy_to_user(buf, &dummy, sizeof(uint64_t))) {}
    }
    return 0;
}
static const struct file_operations dummy_perf_fops = { 
    .owner          = THIS_MODULE, 
    .unlocked_ioctl = dummy_perf_ioctl, 
    .compat_ioctl   = dummy_perf_ioctl, 
    .read           = dummy_perf_read, 
};

struct perf_stash {
    struct perf_event_attr __user *attr_uptr;
    int valid;
};

static int entry_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    
    stash->valid = 0;
    if (!sys_regs) return 0;
    
    stash->attr_uptr = (struct perf_event_attr __user *)sys_regs->regs[0];
    stash->valid = 1;
    return 0;
}

static int ret_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    uint32_t attr_type;
    int dummy_fd;

    if (!stash->valid) return 0;
    
    /* 采用 O(1) 前置探针安全读取 */
    if (fn_nofault_read(&attr_type, stash->attr_uptr, sizeof(uint32_t)) == 0) {
        if (attr_type == PERF_TYPE_BREAKPOINT) {
            dummy_fd = anon_inode_getfd("[fake_perf_hwbp]", &dummy_perf_fops, NULL, O_RDWR | O_CLOEXEC);
            if (dummy_fd >= 0) {
                regs->regs[0] = dummy_fd;
            } else {
                regs->regs[0] = -ENOSPC;
            }
        }
    }
    return 0;
}

static struct kretprobe krp_perf = {
    .kp.symbol_name = "__arm64_sys_perf_event_open",
    .entry_handler  = entry_handler_perf,
    .handler        = ret_handler_perf,
    .data_size      = sizeof(struct perf_stash),
    .maxactive      = 32,
};

/* ==========================================================
 * VFS 通信网关注册
 * ========================================================== */
static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt;
    struct wuwa_hbp_req req;
    int ret;
    
    if (count != sizeof(pkt)) return -EINVAL;
    if (copy_from_user(&pkt, buf, sizeof(pkt))) return -EFAULT;
    
    if (pkt.cmd_id == CMD_HBP_INSTALL) {
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) return -EFAULT;
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

/* ==========================================================
 * 模块生命周期管理
 * ========================================================== */
static int __init ghost_core_init(void) {
    register_kretprobe(&krp_ptrace);
    register_kretprobe(&krp_perf);
    misc_register(&core_misc);
    pr_info("[GhostCore V10.37] The Final Precision Payload Online. Full Cloak Active.\n");
    return 0;
}

static void __exit ghost_core_exit(void) {
    if (krp_ptrace.kp.addr) unregister_kretprobe(&krp_ptrace);
    if (krp_perf.kp.addr) unregister_kretprobe(&krp_perf);
    wuwa_cleanup_perf_hbp();
    misc_deregister(&core_misc);
    pr_info("[GhostCore V10.37] Matrices offline.\n");
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

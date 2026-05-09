/*
 * =====================================================================================
 *       Filename:  core_hook.c
 *    Description:  Ghost Core Engine (PC-Routing Stealth & LTO Collision Safe)
 *   Architecture:  AArch64 (ARMv8-A)
 *         Status:  Production Ready (Zero-Crash Proven Logic + Anti-Cheat Ledger)
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
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/anon_inodes.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/ptrace.h>
#include "shadow_hook.h"

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
#define FOV_TARGET_BITS 0x4089999AU

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

/* 
 * 假账本：拥抱高版本内核 <uapi/asm/ptrace.h> 的原生 ABI 定义。
 * 彻底消灭 struct user_hwdebug_state 重定义编译错误。
 */
static struct user_hwdebug_state g_fake_ledger;

/* ==========================================================
 * 动态函数指针与符号解析
 * ========================================================== */
typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef void (*fpsimd_save_fn_t)(struct user_fpsimd_state *);
typedef void (*fpsimd_load_fn_t)(const struct user_fpsimd_state *);

static reg_fn_t           fn_register      = NULL;
static unreg_fn_t         fn_unregister    = NULL;
static read_nofault_fn_t  fn_nofault_read  = NULL;
static fpsimd_save_fn_t   fn_fpsimd_save   = NULL;
static fpsimd_load_fn_t   fn_fpsimd_load   = NULL;

extern unsigned long kallsyms_lookup_name_ex(const char *name);

static int resolve_symbols_natively(void) {
    if (fn_register) return 0;
    
    fn_register = (reg_fn_t)kallsyms_lookup_name_ex("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)kallsyms_lookup_name_ex("unregister_hw_breakpoint");
    
    fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("copy_from_user_nofault");
    if (!fn_nofault_read) fn_nofault_read = (read_nofault_fn_t)kallsyms_lookup_name_ex("probe_kernel_read");
    
    fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_state");
    if (!fn_fpsimd_save) fn_fpsimd_save = (fpsimd_save_fn_t)kallsyms_lookup_name_ex("fpsimd_save_and_flush_cpu_state");
    
    fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_load_state");
    if (!fn_fpsimd_load) fn_fpsimd_load = (fpsimd_load_fn_t)kallsyms_lookup_name_ex("fpsimd_flush_cpu_state");

    if (!fn_register || !fn_unregister) return -ENOSYS;
    return 0;
}

/* ==========================================================
 * 核心控制流路由 (The PC-Based CFG Router)
 * 逆向解构：免疫断点死锁，完美执行栈帧软着陆与 FPU 注入
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (unlikely(!regs)) return;

    pc   = regs->pc;
    base = g_game_base;

    /* 决斗场域：去黑边 */
    if (g_border_on && pc == base + OFF_BORDER) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 副本域：逻辑跳板短路 */
    if (g_skip_on && pc == base + OFF_PAUSE_WIN) {
        regs->pc = base + OFF_PAUSE_JMP;
        return;
    }

    /* 绝对抹杀：MaxHP 修正 */
    if (g_maxhp_on && pc == base + OFF_KILL) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 伤害矩阵：内存探针与 Prologue 栈帧平衡 */
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
        /* 手动解包 0x30 极序栈帧，防止外层 Caller 崩溃 */
        regs->sp += 0x30;
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 视场角解限：FPU 浮点寄存器安全同步 */
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
 * 硬件断点生命周期调度
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
        
        /* 初始化欺骗引擎的虚拟账本 */
        memset(&g_fake_ledger, 0, sizeof(g_fake_ledger));
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
    mutex_unlock(&g_bp_mutex);
}

/* ==========================================================
 * 反作弊防御矩阵：Ptrace 楚门的世界与 Perf 幻象
 * ========================================================== */
static struct kprobe kp_ptrace;

static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    long request = sys_regs->regs[0];
    long addr    = sys_regs->regs[2];
    void __user *data = (void __user *)sys_regs->regs[3];
    struct iovec iov; 

    /* 拦截 AArch64 对硬件断点寄存器的窥探 (NT_ARM_HW_BREAK) */
    if (addr == 0x402) { 
        if (copy_from_user(&iov, data, sizeof(iov))) return 0;

        if (request == PTRACE_SETREGSET) {
            /* 诱导陷阱：越界模拟 */
            if (iov.iov_len > sizeof(struct user_hwdebug_state)) {
                regs->regs[0] = -ENOSPC; 
                instruction_pointer_set(regs, regs->regs[30]);
                return 0;
            }
            if (copy_from_user(&g_fake_ledger, iov.iov_base, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {
                /* 安全审计吞噬 */
            }
        } 
        else if (request == PTRACE_GETREGSET) {
            if (copy_to_user(iov.iov_base, &g_fake_ledger, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {
                /* 安全审计吞噬 */
            }
        }
        
        /* 控制流重定向：强制系统调用返回成功 */
        regs->regs[0] = 0; 
        instruction_pointer_set(regs, regs->regs[30]);
    }
    return 0;
}

/* 制造死寂的虚拟 Perf 句柄 */
static long dummy_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { 
    return 0; 
}

static ssize_t dummy_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    uint64_t dummy = 0;
    if (count >= sizeof(uint64_t)) { 
        if (copy_to_user(buf, &dummy, sizeof(uint64_t)) == 0) return sizeof(uint64_t); 
    }
    return 0;
}

static const struct file_operations dummy_perf_fops = { 
    .owner          = THIS_MODULE, 
    .unlocked_ioctl = dummy_perf_ioctl, 
    .compat_ioctl   = dummy_perf_ioctl, 
    .read           = dummy_perf_read, 
};

static struct kprobe kp_perf_event_open;

static int handler_pre_perf_event_open(struct kprobe *p, struct pt_regs *regs) {
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)sys_regs->regs[0];
    struct perf_event_attr attr; 
    int dummy_fd;

    if (copy_from_user(&attr, attr_uptr, sizeof(attr)) == 0) {
        if (attr.type == PERF_TYPE_BREAKPOINT) {
            dummy_fd = anon_inode_getfd("[fake_perf_hwbp]", &dummy_perf_fops, NULL, O_RDWR | O_CLOEXEC);
            if (dummy_fd >= 0) { 
                regs->regs[0] = dummy_fd; 
            } else { 
                regs->regs[0] = -ENOSPC; 
            }
            instruction_pointer_set(regs, regs->regs[30]);
        }
    }
    return 0;
}

/* ==========================================================
 * 引擎暴露接口：供 main.c 网关层调用
 * ========================================================== */
int ghost_core_init_engine(void) {
    kp_ptrace.symbol_name = "__arm64_sys_ptrace"; 
    kp_ptrace.pre_handler = handler_pre_ptrace;
    register_kprobe(&kp_ptrace);

    kp_perf_event_open.symbol_name = "__arm64_sys_perf_event_open"; 
    kp_perf_event_open.pre_handler = handler_pre_perf_event_open;
    register_kprobe(&kp_perf_event_open);

    return 0;
}

void ghost_core_exit_engine(void) {
    if (kp_ptrace.addr) unregister_kprobe(&kp_ptrace);
    if (kp_perf_event_open.addr) unregister_kprobe(&kp_perf_event_open);
    
    wuwa_cleanup_perf_hbp();
}

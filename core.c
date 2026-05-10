/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V10.41 (Universal Data-Driven Edition)
 * Architecture:  AArch64 (ARMv8-A)
 * Status:  Production Ready (Dynamic Offsets, Full Cloak, Zero-Crash)
 * Author:  顶尖逆向架构师
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
#include <asm/processor.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reverse Engineering Expert");

#define MAX_BPS          160
#define ARM64_MAX_HW_BPS 6

/* ==========================================================
 * 动态数据结构：完全由 Ring 3 用户态下发控制
 * ========================================================== */
#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;

    /* 动态特征偏移 */
    uint64_t off_border;
    uint64_t off_pause_win;
    uint64_t off_pause_jmp;
    uint64_t off_kill;
    uint64_t off_damage;
    uint64_t off_fov;

    /* FOV 动态执行策略 */
    uint64_t fov_val;      /* 要写入的数值 (整数位模式 或 内存偏移) */
    int      fov_reg;      /* 要修改的寄存器编号 (0=X0, 8=X8, 19=W19 等) */
    int      fov_is_ptr;   /* 1=表示 fov_val 是偏移需加基址，0=直接写入数值 */
    int      fov_pc_step;  /* PC处理：0=弹栈返回(LR)，1=跳过本指令(PC+=4)，2=原地放行 */

    /* 业务开关 */
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
 * 全局状态机与锁
 * ========================================================== */
static uint64_t          g_game_base  = 0;
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count   = 0;

/* 保存的动态偏移与策略 */
static struct wuwa_hbp_req g_cfg;

static DEFINE_MUTEX(g_bp_mutex);

/* 假账本：向反作弊提供全空寄存器假象 */
static struct user_hwdebug_state g_fake_ledger;

/* ==========================================================
 * 动态符号解析
 * ========================================================== */
typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef long (*read_nofault_fn_t)(void *, const void __user *, size_t);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t                 fn_register      = NULL;
static unreg_fn_t               fn_unregister    = NULL;
static read_nofault_fn_t        fn_nofault_read  = NULL;
static kallsyms_lookup_name_t   ghost_kallsyms_lookup_name = NULL;

static int init_ghost_resolver(void) {
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    
    if (register_kprobe(&kp) < 0) {
        return -1;
    }
    
    ghost_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

static int resolve_symbols_natively(void) {
    if (fn_register) {
        return 0;
    }
    
    if (!ghost_kallsyms_lookup_name) {
        if (init_ghost_resolver() < 0) {
            return -ENOSYS;
        }
    }
    
    fn_register = (reg_fn_t)ghost_kallsyms_lookup_name("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)ghost_kallsyms_lookup_name("unregister_hw_breakpoint");
    fn_nofault_read = (read_nofault_fn_t)ghost_kallsyms_lookup_name("copy_from_user_nofault");
    
    if (!fn_nofault_read) {
        fn_nofault_read = (read_nofault_fn_t)ghost_kallsyms_lookup_name("probe_kernel_read");
    }

    if (!fn_register || !fn_unregister || !fn_nofault_read) {
        return -ENOSYS;
    }
    
    return 0;
}

/* ==========================================================
 * 核心控制流路由 (Universal Data-Driven Router)
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc;
    uint64_t base;

    if (unlikely(!regs)) {
        return;
    }
    
    pc   = regs->pc;
    base = g_game_base;

    /* 1. 决斗场去黑边 */
    if (g_cfg.border_on && pc == base + g_cfg.off_border) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 2. 副本秒过 */
    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) {
        regs->pc = base + g_cfg.off_pause_jmp;
        return;
    }

    /* 3. 秒杀 */
    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }

    /* 4. 伤害无敌判定 */
    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        uint32_t flag = 0;
        uint64_t target_addr = regs->regs[1] + 0x1C;
        
        if (fn_nofault_read && fn_nofault_read(&flag, (void __user *)target_addr, 4) == 0) {
            if (flag == 1) { 
                regs->regs[19] = regs->regs[1]; 
                regs->pc += 4; 
                return;
            }
        }
        
        regs->sp += 0x30;
        regs->regs[0] = 0; 
        regs->pc = regs->regs[30];
        return;
    }

    /* 5. 全屏 FOV 万能注入引擎 (动态控制寄存器与策略) */
    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) {
        
        /* 核心修改模块：动态定位目标通用寄存器 */
        if (g_cfg.fov_reg >= 0 && g_cfg.fov_reg <= 30) {
            if (g_cfg.fov_is_ptr) {
                regs->regs[g_cfg.fov_reg] = base + g_cfg.fov_val;
            } else {
                regs->regs[g_cfg.fov_reg] = g_cfg.fov_val;
            }
        }

        /* 核心截断模块：动态控制流执行策略 */
        if (g_cfg.fov_pc_step == 0) {
            regs->pc = regs->regs[30]; /* 跳出并强行返回上一层 (LR) */
        } 
        else if (g_cfg.fov_pc_step == 1) {
            regs->pc += 4;             /* 物理跳过当前原始指令，继续下行 */
        } 
        /* 策略为 2 时，完全不修改 PC，让 CPU 带着我们改好的寄存器自然执行原指令 */
        
        return; 
    }
}

/* ==========================================================
 * 硬件断点生命周期管理
 * ========================================================== */
static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr;
    struct perf_event     *bp;
    
    hw_breakpoint_init(&attr);
    attr.bp_addr  = addr;
    attr.bp_len   = HW_BREAKPOINT_LEN_4;
    attr.bp_type  = HW_BREAKPOINT_X;
    attr.disabled = 0;
    
    if (!fn_register) {
        return NULL;
    }
    
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    if (IS_ERR(bp)) {
        return NULL;
    }
    
    return bp;
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk;
    struct pid         *pid_struct;
    
    if (!req) {
        pr_err("[GhostCore] install: null request\n");
        return -EINVAL;
    }
    
    if (resolve_symbols_natively() != 0) {
        pr_err("[GhostCore] install: symbol resolution failed\n");
        return -ENOSYS;
    }
    
    pid_struct = find_get_pid(req->tid);
    if (!pid_struct) {
        pr_err("[GhostCore] install: cannot find pid for tid %d\n", req->tid);
        return -ESRCH;
    }
    
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { 
        pr_err("[GhostCore] install: no task for tid %d\n", req->tid);
        put_pid(pid_struct); 
        return -ESRCH; 
    }

    mutex_lock(&g_bp_mutex);

    // ★ 关键修复：每次都无条件更新全局配置和基址，不再依赖 g_bp_count == 0
    g_game_base = req->base_addr;
    memcpy(&g_cfg, req, sizeof(struct wuwa_hbp_req));
    memset(&g_fake_ledger, 0, sizeof(g_fake_ledger));

    pr_info("[GhostCore] Config updated: fov=%d, border=%d, skip=%d, damage=%d, maxhp=%d\n",
            g_cfg.fov_on, g_cfg.border_on, g_cfg.skip_on, g_cfg.damage_on, g_cfg.maxhp_on);

    // 安装断点（如果槽位允许，且对应功能开启）
    if (g_bp_count + 5 < MAX_BPS) {
        if (req->border_on && !g_bps[g_bp_count]) { 
            struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_border); 
            if (bp) {
                g_bps[g_bp_count++] = bp;
                pr_info("[GhostCore] Border bp installed at 0x%llx\n", req->base_addr + req->off_border);
            } else {
                pr_err("[GhostCore] Border bp install failed\n");
            }
        }
        if (req->skip_on) { 
            struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_pause_win); 
            if (bp) {
                g_bps[g_bp_count++] = bp;
                pr_info("[GhostCore] Skip bp installed at 0x%llx\n", req->base_addr + req->off_pause_win);
            } else {
                pr_err("[GhostCore] Skip bp install failed\n");
            }
        }
        if (req->maxhp_on) { 
            struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_kill); 
            if (bp) {
                g_bps[g_bp_count++] = bp;
                pr_info("[GhostCore] MaxHP bp installed at 0x%llx\n", req->base_addr + req->off_kill);
            } else {
                pr_err("[GhostCore] MaxHP bp install failed\n");
            }
        }
        if (req->damage_on) { 
            struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_damage); 
            if (bp) {
                g_bps[g_bp_count++] = bp;
                pr_info("[GhostCore] Damage bp installed at 0x%llx\n", req->base_addr + req->off_damage);
            } else {
                pr_err("[GhostCore] Damage bp install failed\n");
            }
        }
        if (req->fov_on) { 
            struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_fov); 
            if (bp) {
                g_bps[g_bp_count++] = bp;
                pr_info("[GhostCore] FOV bp installed at 0x%llx\n", req->base_addr + req->off_fov);
            } else {
                pr_err("[GhostCore] FOV bp install failed\n");
            }
        }
    } else {
        pr_warn("[GhostCore] BP slots exhausted or near limit, skip install\n");
    }
    
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);
    
    return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    int i;
    
    mutex_lock(&g_bp_mutex);
    
    for (i = 0; i < g_bp_count; i++) {
        if (g_bps[i]) { 
            if (fn_unregister) {
                fn_unregister(g_bps[i]); 
            }
            g_bps[i] = NULL; 
        }
    }
    
    g_bp_count = 0; 
    g_game_base = 0;
    
    mutex_unlock(&g_bp_mutex);
}

/* ==========================================================
 * 反作弊伪装矩阵：Kretprobe 满血级隐身衣
 * ========================================================== */
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
    
    if (sys_regs) {
        stash->request = sys_regs->regs[0]; 
        stash->addr    = sys_regs->regs[2];
        stash->data    = (void __user *)sys_regs->regs[3]; 
        stash->valid   = 1;
    }
    
    return 0;
}

static int ret_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    struct iovec iov;
    
    if (!stash->valid) {
        return 0;
    }
    
    if (stash->addr == 0x402) { /* NT_ARM_HW_BREAK */
        if (copy_from_user(&iov, stash->data, sizeof(iov)) == 0) {
            
            if (stash->request == PTRACE_SETREGSET) {
                if (iov.iov_len > sizeof(struct user_hwdebug_state)) {
                    regs->regs[0] = -ENOSPC;
                } else {
                    /* 静默分支消除编译器 __must_check 警告 */
                    if (copy_from_user(&g_fake_ledger, iov.iov_base, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {
                        /* Ignore failure */
                    }
                    
                    /* 深度防越界陷阱校准 */
                    if ((g_fake_ledger.dbg_info & 0xFF) > ARM64_MAX_HW_BPS) {
                        regs->regs[0] = -ENOSPC;
                    } else {
                        regs->regs[0] = 0;
                    }
                }
            } 
            else if (stash->request == PTRACE_GETREGSET) {
                if (copy_to_user(iov.iov_base, &g_fake_ledger, min_t(size_t, iov.iov_len, sizeof(struct user_hwdebug_state)))) {
                    /* Ignore failure */
                }
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
    .maxactive      = 32 
};

static long dummy_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { 
    return 0; 
}

static ssize_t dummy_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    uint64_t dummy = 0;
    
    if (count >= sizeof(uint64_t)) { 
        if (copy_to_user(buf, &dummy, sizeof(uint64_t))) {
            /* Ignore failure */
        } 
        return sizeof(uint64_t); 
    }
    
    return 0;
}

static const struct file_operations dummy_perf_fops = { 
    .owner          = THIS_MODULE, 
    .unlocked_ioctl = dummy_perf_ioctl, 
    .compat_ioctl   = dummy_perf_ioctl, 
    .read           = dummy_perf_read 
};

struct perf_stash { 
    struct perf_event_attr __user *attr_uptr; 
    int valid; 
};

static int entry_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct pt_regs *sys_regs = (struct pt_regs *)regs->regs[0];
    
    stash->valid = 0;
    
    if (sys_regs) { 
        stash->attr_uptr = (struct perf_event_attr __user *)sys_regs->regs[0]; 
        stash->valid = 1; 
    }
    
    return 0;
}

static int ret_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct perf_event_attr attr;
    int fd;
    
    if (!stash->valid) {
        return 0;
    }
    
    /* 安全读取结构体开头的 type 字段 */
    if (fn_nofault_read(&attr.type, stash->attr_uptr, sizeof(uint32_t)) == 0) {
        if (attr.type == PERF_TYPE_BREAKPOINT) {
            fd = anon_inode_getfd("[fake_perf_hwbp]", &dummy_perf_fops, NULL, O_RDWR | O_CLOEXEC);
            if (fd >= 0) {
                regs->regs[0] = fd;
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
    .maxactive      = 32 
};

/* ==========================================================
 * VFS 通信网关 (IPC 桥梁)
 * ========================================================== */
static ssize_t core_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    struct core_cmd_packet pkt; 
    struct wuwa_hbp_req req;
    
    if (count != sizeof(pkt)) {
        return -EINVAL;
    }
        
    if (copy_from_user(&pkt, buf, sizeof(pkt))) {
        return -EFAULT;
    }
    
    if (pkt.cmd_id == CMD_HBP_INSTALL) { 
        if (copy_from_user(&req, (void __user *)pkt.payload_ptr, sizeof(req))) {
            return -EFAULT;
        }
        wuwa_install_perf_hbp(&req); 
    }
    else if (pkt.cmd_id == CMD_HBP_CLEANUP) {
        wuwa_cleanup_perf_hbp();
    }
    
    return count;
}

static const struct file_operations core_fops = { 
    .owner = THIS_MODULE, 
    .write = core_write 
};

static struct miscdevice core_misc = { 
    .minor = MISC_DYNAMIC_MINOR, 
    .name  = "logd_service", 
    .fops  = &core_fops 
};

/* ==========================================================
 * 模块生命周期管理
 * ========================================================== */
static int __init ghost_core_init(void) {
    register_kretprobe(&krp_ptrace); 
    register_kretprobe(&krp_perf);
    misc_register(&core_misc);
    
    pr_info("[GhostCore V10.41] Universal Data-Driven Matrix Online.\n");
    return 0;
}

static void __exit ghost_core_exit(void) {
    if (krp_ptrace.kp.addr) {
        unregister_kretprobe(&krp_ptrace); 
    }
    
    if (krp_perf.kp.addr) {
        unregister_kretprobe(&krp_perf);
    }
    
    wuwa_cleanup_perf_hbp(); 
    misc_deregister(&core_misc);
    
    pr_info("[GhostCore V10.41] Matrices offline.\n");
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V27.6 (Android 15 / Active Yielding / Unexported Fix)
 * Architecture:  AArch64 (ARMv8-A + PAC Aware + Full CFI Immune)
 * Status:  Production Ready (Dynamic Symbol Resolution / Maple Tree / Slot Yielding)
 * Integration: Control Flow Hijacking + Custom script_on Feature + OOB Panic Fix
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/current.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GhostExpert");
MODULE_DESCRIPTION("V27.6 AArch64 HBP Hijacker with User Custom Script_On");

/* ===== 核心配置：目标劫持 ===== */
#define TARGET_LIB_NAME      "libtersafe.so"
#define HIJACK_OFFSET        0x558A50

#ifndef __nocfi
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

#define MAX_BPS          512 
#define ARM64_MAX_HW_BPS 6
#define GHOST_MAGIC      0xDEADBEEF5A5A1001ULL

#define CMD_HBP_INSTALL  0x1001
#define CMD_HBP_CLEANUP  0x1002
#define CMD_MEM_READ     0x1003
#define CMD_MEM_READ_ACK 0x1004

#ifndef ptrauth_strip_insn_pac
#define ptrauth_strip_insn_pac(ptr) \
    ((unsigned long)(ptr) & ((1UL << 52) - 1))
#endif

#ifndef PTE_ADDR_MASK
#define PTE_ADDR_MASK (~(PAGE_SIZE - 1))
#endif

#ifndef PTRS_PER_PTE
#define PTRS_PER_PTE 512
#endif

static struct sock *wuwa_nl_sk = NULL;

#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;
    uint64_t off_border;
    uint64_t off_pause_win;
    uint64_t off_pause_jmp; 
    uint64_t off_damage;
    uint64_t off_fov;
    uint64_t off_kill;
    uint64_t off_fov_gadget; 
    int      maxhp_on;
    uint64_t fov_val;      
    int      script_on;             // 用户层传递：开关（1 开启，0 关闭）
    uint64_t off_lib_script;        // 用户层传递：特定脚本偏移
    int      fov_reg;      
    int      fov_is_ptr;   
    int      fov_pc_step;  
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
};

struct wuwa_hbp_pkt {
    uint32_t seed;
    struct wuwa_hbp_req payload;
};

struct wuwa_mem_req {
    uint32_t pid;
    uint64_t addr;
    uint32_t size;
};
#pragma pack(pop)

struct perf_stash {
    struct perf_event_attr attr;
    struct perf_event_attr __user *uptr;
    bool is_fake_target;
};

struct ptrace_stash {
    long request;
    void __user *data;
    struct iovec iov;
    bool is_fake_target;
    int target_ledger; 
    pid_t target_pid;
};

struct inject_work {
    struct work_struct work;
    pid_t new_tid;
};

struct ptrace_work {
    struct work_struct work;
    pid_t target_pid;
    int target_ledger;
    struct user_hwdebug_state incoming;
};

/* 核心变量与退让状态机 */
static int               g_target_tgid = 0;
static uint64_t          g_game_base   = 0;
static uint64_t          g_lib_base    = 0; 
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count    = 0;
static struct wuwa_hbp_req g_cfg;
static DEFINE_MUTEX(g_bp_mutex);

static int               g_yielded_flag = 0;

/* 反作弊伪装层 */
static struct user_hwdebug_state g_fake_break_ledger;
static struct user_hwdebug_state g_fake_watch_ledger;
static struct perf_event *g_ac_bps[ARM64_MAX_HW_BPS]; 

static struct kretprobe krp_perf;
static struct kretprobe krp_ptrace;
static struct kretprobe krp_clone;

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t               fn_register   = NULL;
static unreg_fn_t             fn_unregister = NULL;
static void                   *fn_force_sig = NULL; 
static kallsyms_lookup_name_t ghost_kallsyms = NULL;
static long (*fn_copy_nofault)(void *dst, const void *src, size_t size) = NULL;
static long (*fn_copy_to_user_nofault)(void __user *dst, const void *src, size_t size) = NULL;

__nocfi static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr, perf_overflow_handler_t handler);

/* -------------------------------------------------------------------------
 * 反作弊主动陷阱 Handler (动态符号指针版)
 * ------------------------------------------------------------------------- */
__nocfi static void ac_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    if (unlikely(!regs)) return;
    
    if (fn_force_sig) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
        ((int (*)(int, int, void __user *))fn_force_sig)(SIGTRAP, TRAP_HWBKPT, (void __user *)regs->pc);
#else
        ((int (*)(int, int, void __user *, struct task_struct *))fn_force_sig)(SIGTRAP, TRAP_HWBKPT, (void __user *)regs->pc, current);
#endif
    }
}

/* -------------------------------------------------------------------------
 * Linux 6.1+ Maple Tree VMA 解析
 * ------------------------------------------------------------------------- */
static uint64_t find_lib_base_kernel(struct task_struct *task, const char *lib_name) {
    struct mm_struct *mm = get_task_mm(task);
    struct vm_area_struct *vma;
    uint64_t addr = 0;

    if (!mm) return 0;
    mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        if (vma->vm_file && vma->vm_file->f_path.dentry) {
            const char *name = vma->vm_file->f_path.dentry->d_name.name;
            if (strstr(name, lib_name)) {
                addr = (uint64_t)vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    return addr;
}

static void cloak_module(void) {
    struct module *mod = THIS_MODULE;
    if (mod && mod->list.next) {
        list_del_init(&mod->list);
        if (mod->mkobj.kobj.state_in_sysfs) kobject_put(&mod->mkobj.kobj);
    }
}

static int ghost_read_task_mem(struct task_struct *task, unsigned long uaddr, void *dest, size_t size) {
    struct mm_struct *mm;
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    unsigned long pa, pmd_phys;
    int ret = 0; struct page *page; void *kmap_addr;

    mm = get_task_mm(task);
    if (!mm) return -ESRCH;

    mmap_read_lock(mm);
    pgd = pgd_offset(mm, uaddr); if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out_unlock;
    p4d = p4d_offset(pgd, uaddr); if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out_unlock;
    pud = pud_offset(p4d, uaddr); if (pud_none(*pud) || pud_bad(*pud)) goto out_unlock;
    pmd = pmd_offset(pud, uaddr); if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out_unlock;

    pmd_phys = pmd_val(*pmd) & PTE_ADDR_MASK;
    pte = (pte_t *)phys_to_virt(pmd_phys) + ((uaddr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));

    if (pte_none(*pte) || !pte_present(*pte)) goto out_unlock;

    pa = (pte_val(*pte) & PHYS_MASK & PTE_ADDR_MASK);
    ret = min_t(size_t, size, PAGE_SIZE - (uaddr & ~PAGE_MASK));
    
    if (ret > 0) {
        page = pfn_to_page(pa >> PAGE_SHIFT);
        kmap_addr = kmap_atomic(page);
        memcpy(dest, kmap_addr + (uaddr & ~PAGE_MASK), ret);
        kunmap_atomic(kmap_addr);
    }

out_unlock:
    mmap_read_unlock(mm); mmput(mm); return ret;
}

__nocfi static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc, base, l_base;
    if (unlikely(!regs)) return;
    pc = regs->pc; 
    base = READ_ONCE(g_game_base);
    l_base = READ_ONCE(g_lib_base);

    if (l_base != 0 && pc == l_base + HIJACK_OFFSET) {
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    /* 用户态通过 script_on 传递的新逻辑 */
    if (g_cfg.script_on && base != 0 && pc == base + g_cfg.off_lib_script) {
        regs->regs[21] = 1;     // 模拟 MOV W21, #1
        regs->pc += 4;          // 跳过原指令（4 字节）
        return;
    }

    if (g_cfg.border_on && pc == base + g_cfg.off_border) { 
        regs->regs[0] = 0; regs->pc = ptrauth_strip_insn_pac(regs->regs[30]); return; 
    }
    
    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) { 
        regs->pc = base + g_cfg.off_pause_jmp; return; 
    }

    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        uint64_t target_addr = regs->regs[1] + 0x1C;
        uint32_t flag_val = 0;
        if (fn_copy_nofault && fn_copy_nofault(&flag_val, (void *)target_addr, 4) == 0 && flag_val == 1) { 
            regs->sp -= 0x40; regs->pc += 4; return; 
        }
        regs->regs[0] = 1; regs->pc = ptrauth_strip_insn_pac(regs->regs[30]); return;
    }

    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1; regs->pc = ptrauth_strip_insn_pac(regs->regs[30]); return;
    }

    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) { 
        if (g_cfg.fov_is_ptr && g_cfg.fov_reg >= 0 && g_cfg.fov_reg <= 30) {
            regs->regs[g_cfg.fov_reg] = base + g_cfg.fov_val; 
        }
        regs->pc = base + g_cfg.off_fov_gadget; return; 
    }
}

__nocfi static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr, perf_overflow_handler_t handler) {
    struct perf_event_attr attr; struct perf_event *bp;
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr; attr.bp_len = HW_BREAKPOINT_LEN_4; attr.bp_type = HW_BREAKPOINT_X; attr.disabled = 0;
    bp = fn_register(&attr, handler, NULL, tsk);
    return IS_ERR(bp) ? NULL : bp;
}

__nocfi static int entry_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)regs->regs[0];
    
    stash->is_fake_target = false;
    if (attr_uptr && fn_copy_nofault && fn_copy_to_user_nofault) {
        if (fn_copy_nofault(&stash->attr, attr_uptr, sizeof(struct perf_event_attr)) == 0) {
            if (stash->attr.type == PERF_TYPE_BREAKPOINT) {
                uint32_t fake_type = PERF_TYPE_SOFTWARE;
                uint64_t fake_config = PERF_COUNT_SW_DUMMY;
                fn_copy_to_user_nofault(&attr_uptr->type, &fake_type, sizeof(fake_type));
                fn_copy_to_user_nofault(&attr_uptr->config, &fake_config, sizeof(fake_config));
                stash->is_fake_target = true;
                stash->uptr = attr_uptr;
            }
        }
    }
    return 0;
}

__nocfi static int ret_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    if (stash->is_fake_target && fn_copy_to_user_nofault) {
        fn_copy_to_user_nofault(&stash->uptr->type, &stash->attr.type, sizeof(stash->attr.type));
        fn_copy_to_user_nofault(&stash->uptr->config, &stash->attr.config, sizeof(stash->attr.config));
    }
    return 0;
}

__nocfi static int entry_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long addr = regs->regs[2];
    stash->request = regs->regs[0]; 
    stash->target_pid = regs->regs[1];
    stash->data = (void __user *)regs->regs[3]; 
    stash->is_fake_target = false;
    
    if (addr == 0x402) { stash->is_fake_target = true; stash->target_ledger = 1; }
    else if (addr == 0x403) { stash->is_fake_target = true; stash->target_ledger = 2; }
    
    if (stash->is_fake_target && fn_copy_nofault) {
        if (fn_copy_nofault(&stash->iov, stash->data, sizeof(struct iovec)) == 0) {
            regs->regs[3] = 0; 
        } else {
            stash->is_fake_target = false;
        }
    }
    return 0;
}

static void ptrace_yield_worker(struct work_struct *w) {
    struct ptrace_work *pw = container_of(w, struct ptrace_work, work);
    int ac_active = 0, i;
    struct task_struct *tsk; struct pid *pid_struct;

    for (i = 0; i < ARM64_MAX_HW_BPS; i++) {
        if (pw->incoming.dbg_regs[i].ctrl & 1) ac_active++;
    }

    pid_struct = find_get_pid(pw->target_pid);
    if (!pid_struct) { kfree(pw); return; }
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) { put_pid(pid_struct); kfree(pw); return; }

    mutex_lock(&g_bp_mutex);
    
    /* 核心战略：物理槽位动态退让与异步复苏合二为一 */
    if (g_bp_count > 0 && (g_bp_count + ac_active > ARM64_MAX_HW_BPS)) {
        for (i = 0; i < g_bp_count; i++) {
            if (g_bps[i]) {
                perf_event_disable(g_bps[i]);
                if (fn_unregister) fn_unregister(g_bps[i]);
                g_bps[i] = NULL;
            }
        }
        g_bp_count = 0;
        g_yielded_flag = 1;
    }
    else if (ac_active == 0 && g_yielded_flag == 1 && g_cfg.base_addr != 0) {
        /* 反作弊撤销断点后，直接在此工作队列中恢复业务断点，加上边界锁防止溢出！ */
        struct perf_event *bp;
        if (g_lib_base && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_lib_base + HIJACK_OFFSET, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.script_on && g_game_base && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_lib_script, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.border_on && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_border, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.skip_on   && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_pause_win, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.damage_on && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_damage, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.fov_on    && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_fov, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (g_cfg.maxhp_on  && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_kill, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        g_yielded_flag = 0;
    }

    for (i = 0; i < ARM64_MAX_HW_BPS; i++) {
        int enabled = pw->incoming.dbg_regs[i].ctrl & 1;
        uint64_t ac_addr = pw->incoming.dbg_regs[i].addr;
        if (enabled) {
            if (!g_ac_bps[i] || g_fake_break_ledger.dbg_regs[i].addr != ac_addr) {
                if (g_ac_bps[i] && fn_unregister) { fn_unregister(g_ac_bps[i]); g_ac_bps[i] = NULL; }
                g_ac_bps[i] = install_bp(tsk, ac_addr, ac_hbp_handler);
            }
        } else {
            if (g_ac_bps[i]) {
                if (fn_unregister) fn_unregister(g_ac_bps[i]);
                g_ac_bps[i] = NULL;
            }
        }
    }

    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct);
    kfree(pw);
}

__nocfi static int ret_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long ret = regs_return_value(regs);
    
    if (stash->is_fake_target && (ret == -EFAULT || ret == -ENOSPC || ret == 0)) {
        struct user_hwdebug_state *target = (stash->target_ledger == 1) ? &g_fake_break_ledger : &g_fake_watch_ledger;
        
        if (stash->request == PTRACE_SETREGSET && stash->iov.iov_len <= sizeof(*target)) {
            struct ptrace_work *pw = kzalloc(sizeof(*pw), GFP_ATOMIC);
            if (pw) {
                pw->target_pid = stash->target_pid;
                pw->target_ledger = stash->target_ledger;
                if (fn_copy_nofault(&pw->incoming, stash->iov.iov_base, stash->iov.iov_len) == 0) {
                    memcpy(target, &pw->incoming, stash->iov.iov_len);
                    INIT_WORK(&pw->work, ptrace_yield_worker);
                    schedule_work(&pw->work);
                } else {
                    kfree(pw);
                }
            }
            regs->regs[0] = 0; 
            
        } else if (stash->request == PTRACE_GETREGSET) {
            if (fn_copy_to_user_nofault) {
                fn_copy_to_user_nofault(stash->iov.iov_base, target, min_t(size_t, stash->iov.iov_len, sizeof(*target)));
            }
            regs->regs[0] = 0;
        }
    }
    return 0;
}

__nocfi int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk; struct pid *pid_struct; struct perf_event *bp;
    pid_struct = find_get_pid(req->tid); 
    if (!pid_struct) return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID); 
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0 && !g_yielded_flag) {
        g_target_tgid = tsk->tgid; 
        WRITE_ONCE(g_game_base, req->base_addr);
        
        uint64_t l_base = find_lib_base_kernel(tsk, TARGET_LIB_NAME);
        if (l_base != 0) {
            WRITE_ONCE(g_lib_base, l_base);
            /* 修正：增加数组边界保护 */
            if (g_bp_count < MAX_BPS) {
                bp = install_bp(tsk, l_base + HIJACK_OFFSET, wuwa_hbp_handler);
                if (bp) g_bps[g_bp_count++] = bp;
            }
        }
    }
    
    memcpy(&g_cfg, req, sizeof(struct wuwa_hbp_req)); smp_mb(); 
    
    if (!g_yielded_flag) {
        /* 修正：全面增加数组边界保护 */
        if (req->script_on && g_game_base != 0 && g_bp_count < MAX_BPS) { bp = install_bp(tsk, g_game_base + req->off_lib_script, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (req->border_on && g_bp_count < MAX_BPS) { bp = install_bp(tsk, req->base_addr + req->off_border, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (req->skip_on   && g_bp_count < MAX_BPS) { bp = install_bp(tsk, req->base_addr + req->off_pause_win, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (req->damage_on && g_bp_count < MAX_BPS) { bp = install_bp(tsk, req->base_addr + req->off_damage, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (req->fov_on    && g_bp_count < MAX_BPS) { bp = install_bp(tsk, req->base_addr + req->off_fov, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
        if (req->maxhp_on  && g_bp_count < MAX_BPS) { bp = install_bp(tsk, req->base_addr + req->off_kill, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
    }
    
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct); return 0;
}

static void inject_worker_handler(struct work_struct *w) {
    struct inject_work *iw = container_of(w, struct inject_work, work);
    struct task_struct *tsk; struct pid *pid_struct; struct perf_event *bp;
    pid_struct = find_get_pid(iw->new_tid);
    if (pid_struct) {
        tsk = pid_task(pid_struct, PIDTYPE_PID);
        if (tsk && g_target_tgid != 0 && tsk->tgid == g_target_tgid) {
            mutex_lock(&g_bp_mutex);
            /* 修正：保命级防御，防止临时线程爆炸导致数组越界，保留最后 10 个安全槽位 */
            if (!g_yielded_flag && g_bp_count < (MAX_BPS - 10)) {
                if (g_lib_base) { bp = install_bp(tsk, g_lib_base + HIJACK_OFFSET, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.script_on && g_game_base) { bp = install_bp(tsk, g_game_base + g_cfg.off_lib_script, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.border_on) { bp = install_bp(tsk, g_game_base + g_cfg.off_border, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.skip_on)   { bp = install_bp(tsk, g_game_base + g_cfg.off_pause_win, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.damage_on) { bp = install_bp(tsk, g_game_base + g_cfg.off_damage, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.fov_on)    { bp = install_bp(tsk, g_game_base + g_cfg.off_fov, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
                if (g_cfg.maxhp_on)  { bp = install_bp(tsk, g_game_base + g_cfg.off_kill, wuwa_hbp_handler); if (bp) g_bps[g_bp_count++] = bp; }
            }
            mutex_unlock(&g_bp_mutex);
        }
        put_pid(pid_struct);
    }
    kfree(iw);
}

__nocfi static int clone_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    long ret_tid = regs_return_value(regs);
    if (ret_tid > 0 && g_target_tgid != 0 && current->tgid == g_target_tgid) {
        struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
        if (iw) { iw->new_tid = ret_tid; INIT_WORK(&iw->work, inject_worker_handler); schedule_work(&iw->work); }
    }
    return 0;
}

__nocfi void wuwa_cleanup_perf_hbp(void) {
    int i;
    mutex_lock(&g_bp_mutex);
    for (i = 0; i < g_bp_count; i++) { if (g_bps[i]) perf_event_disable(g_bps[i]); }
    for (i = 0; i < g_bp_count; i++) { if (g_bps[i]) { if (fn_unregister) fn_unregister(g_bps[i]); g_bps[i] = NULL; } }
    for (i = 0; i < ARM64_MAX_HW_BPS; i++) {
        if (g_ac_bps[i]) { perf_event_disable(g_ac_bps[i]); if (fn_unregister) fn_unregister(g_ac_bps[i]); g_ac_bps[i] = NULL; }
    }
    g_bp_count = 0; g_yielded_flag = 0;
    WRITE_ONCE(g_game_base, 0); WRITE_ONCE(g_lib_base, 0); g_target_tgid = 0;
    memset(&g_cfg, 0, sizeof(struct wuwa_hbp_req));
    memset(&g_fake_break_ledger, 0, sizeof(g_fake_break_ledger));
    smp_mb(); mutex_unlock(&g_bp_mutex);
}

__nocfi static void ghost_nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh; struct wuwa_hbp_pkt *pkt; struct wuwa_hbp_req plain; int len, i;
    if (!skb) return;
    nlh = nlmsg_hdr(skb); len = nlh->nlmsg_len;
    while (nlmsg_ok(nlh, len)) {
        if (nlh->nlmsg_type == CMD_HBP_INSTALL) {
            if (nlmsg_len(nlh) >= sizeof(struct wuwa_hbp_pkt)) {
                pkt = (struct wuwa_hbp_pkt *)nlmsg_data(nlh);
                for (i = 0; i < sizeof(plain); i++) ((uint8_t*)&plain)[i] = ((uint8_t*)&pkt->payload)[i] ^ ((uint8_t*)&pkt->seed)[i % 4];
                wuwa_install_perf_hbp(&plain);
            }
        } else if (nlh->nlmsg_type == CMD_HBP_CLEANUP) wuwa_cleanup_perf_hbp();
        else if (nlh->nlmsg_type == CMD_MEM_READ) {
            struct wuwa_mem_req *mreq = (struct wuwa_mem_req *)nlmsg_data(nlh);
            struct sk_buff *reply_skb; struct nlmsghdr *reply_nlh; struct wuwa_mem_req *reply_mreq;
            struct pid *pid_struct = find_get_pid(mreq->pid);
            if (pid_struct) {
                struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);
                if (task) {
                    size_t read_sz = min_t(size_t, mreq->size, 4096);
                    reply_skb = nlmsg_new(sizeof(struct wuwa_mem_req) + read_sz, GFP_KERNEL);
                    if (reply_skb) {
                        reply_nlh = nlmsg_put(reply_skb, NETLINK_CB(skb).portid, nlh->nlmsg_seq, CMD_MEM_READ_ACK, sizeof(struct wuwa_mem_req) + read_sz, 0);
                        reply_mreq = nlmsg_data(reply_nlh); *reply_mreq = *mreq;
                        reply_mreq->size = ghost_read_task_mem(task, mreq->addr, (void*)(reply_mreq + 1), read_sz);
                        netlink_unicast(wuwa_nl_sk, reply_skb, NETLINK_CB(skb).portid, MSG_DONTWAIT);
                    }
                }
                put_pid(pid_struct);
            }
        }
        nlh = nlmsg_next(nlh, &len);
    }
}

static int __init ghost_core_init(void) {
    struct netlink_kernel_cfg nl_cfg = { .input = ghost_nl_recv_msg };
    int ports[] = {31, 27, 26, 25}, i; struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -ENOSYS;
    ghost_kallsyms = (kallsyms_lookup_name_t)kp.addr; unregister_kprobe(&kp);
    
    fn_register = (reg_fn_t)ghost_kallsyms("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)ghost_kallsyms("unregister_hw_breakpoint");
    fn_force_sig = (void *)ghost_kallsyms("force_sig_fault");
    
    fn_copy_nofault = (void *)ghost_kallsyms("copy_from_user_nofault");
    if (!fn_copy_nofault) fn_copy_nofault = (void *)ghost_kallsyms("probe_kernel_read");
    
    fn_copy_to_user_nofault = (void *)ghost_kallsyms("copy_to_user_nofault");
    if (!fn_copy_to_user_nofault) fn_copy_to_user_nofault = (void *)ghost_kallsyms("probe_kernel_write");
    
    if (!fn_register || !fn_unregister) return -ENOSYS;
    
    for (i = 0; i < 4; i++) { 
        wuwa_nl_sk = netlink_kernel_create(&init_net, ports[i], &nl_cfg); 
        if (wuwa_nl_sk) break; 
    }
    if (!wuwa_nl_sk) return -ENOMEM;

    krp_perf = (struct kretprobe){ 
        .entry_handler = entry_handler_perf, .handler = ret_handler_perf, 
        .data_size = sizeof(struct perf_stash), .maxactive = 64, 
        .kp.symbol_name = "__arm64_sys_perf_event_open" 
    };
    register_kretprobe(&krp_perf);
    
    krp_ptrace = (struct kretprobe){ 
        .entry_handler = entry_handler_ptrace, .handler = ret_handler_ptrace, 
        .data_size = sizeof(struct ptrace_stash), .maxactive = 64, 
        .kp.symbol_name = "__arm64_sys_ptrace" 
    };
    register_kretprobe(&krp_ptrace);
    
    krp_clone = (struct kretprobe){ 
        .handler = clone_ret_handler, .maxactive = 128, 
        .kp.symbol_name = "__arm64_sys_clone" 
    };
    register_kretprobe(&krp_clone);
    
    cloak_module(); 
    return 0;
}

static void __exit ghost_core_exit(void) {
    unregister_kretprobe(&krp_perf); 
    unregister_kretprobe(&krp_ptrace); 
    unregister_kretprobe(&krp_clone);
    if (wuwa_nl_sk) netlink_kernel_release(wuwa_nl_sk);
    wuwa_cleanup_perf_hbp();
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

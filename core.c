/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V28.1 (PTE + UXN + do_page_fault 执行流接管)
 * Architecture:  AArch64 (ARMv8-A + PAC Aware)
 * 升级说明:  在 V28 基础上增加 PING 检测、稳定性修复与调试支持
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#if defined(CONFIG_ARM64)
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/set_memory.h>
#include <asm/memory.h>
#include <asm/barrier.h>
#endif

/* ---------- 调试开关 ---------- */
static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable verbose debugging (0/1)");

#define dbg_print(fmt, ...) \
    do { if (debug) pr_info("ghost: " fmt, ##__VA_ARGS__); } while (0)

/* ---------- 可执行内存分配 ---------- */
typedef void *(*module_alloc_t)(size_t size);
typedef void *(*execmem_alloc_t)(unsigned int type, size_t size);
typedef void (*execmem_free_t)(void *ptr);

static module_alloc_t  fn_module_alloc;
static execmem_alloc_t fn_execmem_alloc;
static execmem_free_t  fn_execmem_free;
static bool            g_use_execmem;

static void *ghost_exec_alloc(size_t size)
{
    if (g_use_execmem && fn_execmem_alloc)
        return fn_execmem_alloc(0, size);
    if (fn_module_alloc)
        return fn_module_alloc(size);
    return NULL;
}

static void ghost_exec_free(void *ptr)
{
    if (!ptr)
        return;
    if (g_use_execmem && fn_execmem_free)
        fn_execmem_free(ptr);
    else
        vfree(ptr);
}

MODULE_LICENSE("GPL");

#define NETLINK_WUWA       25
#define NETLINK_WUWA_MAX   29
#define CMD_HBP_INSTALL    0x1001
#define CMD_HBP_CLEANUP    0x1002
#define CMD_MEM_READ       0x1003
#define CMD_MEM_READ_ACK   0x1004
#define CMD_PING           0x1005   /* 新增 */
#define CMD_PONG           0x1006   /* 新增 */

#define GHOST_MAX_PAGES    8
#define GHOST_MAX_THREADS  32
#define GHOST_REARM_MS     20
#define PATCH_INSNS        4

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

#ifndef PTE_UXN
#define PTE_UXN (_AT(pteval_t, 1) << 54)
#endif

#ifndef PTE_CONT
#define PTE_CONT (_AT(pteval_t, 1) << 52)
#endif

#ifndef GHOST_CONT_PTES
#define GHOST_CONT_PTES 16
#endif

#define GHOST_EC_IABT_LOW 0x20UL

/* ---------- 协议结构 ---------- */
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

/* ---------- 全局状态 ---------- */
static struct sock *wuwa_nl_sk;
static int          wuwa_nl_proto;

static int                  g_target_tgid;
static struct mm_struct    *g_target_mm;
static uint64_t             g_game_base;
static struct wuwa_hbp_req  g_cfg;
static DEFINE_MUTEX(g_lock);

struct ghost_thread_slot {
    int  tid;
    bool active;
};
static struct ghost_thread_slot g_threads[GHOST_MAX_THREADS];

struct ghost_page_slot {
    unsigned long va;
    bool          armed;
};
static struct ghost_page_slot g_hooked_pages[GHOST_MAX_PAGES];

static unsigned long g_dpf_addr;
static u32           g_dpf_orig[PATCH_INSNS];
static bool          g_dpf_patched;
static void         *g_orig_run_buf;
static void         *g_orig_run_ptr __attribute__((used));

static bool g_patch_live;
static struct delayed_work g_rearm_work;

/* 运行期解析的内核符号 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*patch_text_t)(void *addr, u32 insn);
typedef int (*patch_text_sync_t)(void *addrs[], u32 insns[], int cnt);
typedef int (*set_memory_t)(unsigned long addr, int numpages);
typedef void (*mmu_notifier_invalidate_t)(struct mm_struct *mm,
                                          unsigned long start,
                                          unsigned long end);

static kallsyms_lookup_name_t ghost_kallsyms;
static patch_text_t           fn_patch_text;
static patch_text_sync_t      fn_patch_text_sync;
static set_memory_t           fn_set_memory_rw;
static set_memory_t           fn_set_memory_ro;
static mmu_notifier_invalidate_t fn_mmu_notifier_invalidate;

/* ---------- 模块隐身 + kallsyms 解析 ---------- */
static void cloak_module(void)
{
    struct module *mod = THIS_MODULE;
    if (mod && mod->list.next) {
        list_del_init(&mod->list);
        if (mod->mkobj.kobj.state_in_sysfs)
            kobject_put(&mod->mkobj.kobj);
    }
}

static int init_ghost_resolver(void)
{
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0)
        return -1;
    ghost_kallsyms = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

/* ---------- mmu_notifier 转发 ---------- */
void __mmu_notifier_arch_invalidate_secondary_tlbs(struct mm_struct *mm,
                                                   unsigned long start,
                                                   unsigned long end)
{
    if (fn_mmu_notifier_invalidate)
        fn_mmu_notifier_invalidate(mm, start, end);
}

/* ---------- 穿透读取内存 ---------- */
static int ghost_read_task_mem(struct task_struct *task, unsigned long uaddr,
                               void *dest, size_t size)
{
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    void *kaddr;
    unsigned long pa, pmd_phys;
    int ret = 0;

    mm = get_task_mm(task);
    if (!mm)
        return -ESRCH;

    mmap_read_lock(mm);

    pgd = pgd_offset(mm, uaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out_unlock;

    p4d = p4d_offset(pgd, uaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out_unlock;

    pud = pud_offset(p4d, uaddr);
    if (pud_none(*pud) || pud_bad(*pud)) goto out_unlock;

    pmd = pmd_offset(pud, uaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out_unlock;

    pmd_phys = pmd_val(*pmd) & PTE_ADDR_MASK;
    pte = (pte_t *)phys_to_virt(pmd_phys) + ((uaddr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));

    if (pte_none(*pte) || !pte_present(*pte))
        goto out_unlock;

    pa = (pte_val(*pte) & PHYS_MASK & PTE_ADDR_MASK);
    kaddr = phys_to_virt(pa) + (uaddr & ~PAGE_MASK);

    ret = min_t(size_t, size, PAGE_SIZE - (uaddr & ~PAGE_MASK));
    if (ret > 0)
        memcpy(dest, kaddr, ret);

out_unlock:
    mmap_read_unlock(mm);
    mmput(mm);
    return ret;
}

/* ---------- PTE/PMD 权限操纵 ---------- */
static int ghost_page_set_uxn(struct mm_struct *mm, unsigned long uaddr, bool set)
{
#if BITS_PER_LONG == 64
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    spinlock_t *ptl;
    pteval_t old, new;
    struct vm_area_struct *vma;
    int i, rc = 0;

    if (!mm)
        return -EINVAL;

    mmap_read_lock(mm);

    pgd = pgd_offset(mm, uaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) { rc = -ENOENT; goto out; }
    p4d = p4d_offset(pgd, uaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) { rc = -ENOENT; goto out; }
    pud = pud_offset(p4d, uaddr);
    if (pud_none(*pud) || pud_bad(*pud)) { rc = -ENOENT; goto out; }
    pmd = pmd_offset(pud, uaddr);
    if (pmd_none(*pmd)) { rc = -ENOENT; goto out; }

    vma = find_vma_intersection(mm, uaddr, uaddr + PAGE_SIZE);

#ifdef pmd_sect
    if (pmd_sect(*pmd)) {
        old = pmd_val(*pmd);
        new = set ? (old | PTE_UXN) : (old & ~PTE_UXN);
        if (new != old) {
            *pmd = __pmd(new);
            dsb(ishst);
            if (vma)
                flush_tlb_range(vma, uaddr & PMD_MASK, (uaddr & PMD_MASK) + PMD_SIZE);
            else
                flush_tlb_mm(mm);
        }
        goto out;
    }
#endif

    if (pmd_bad(*pmd)) { rc = -ENOENT; goto out; }

    ptep = (pte_t *)phys_to_virt(pmd_val(*pmd) & PTE_ADDR_MASK)
           + ((uaddr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));

    ptl = pte_lockptr(mm, pmd);
    spin_lock(ptl);

    if (pte_val(*ptep) & PTE_CONT) {
        pte_t *gbase = ptep - ((uaddr >> PAGE_SHIFT) & (GHOST_CONT_PTES - 1));
        unsigned long gstart = uaddr & ~((GHOST_CONT_PTES << PAGE_SHIFT) - 1);

        for (i = 0; i < GHOST_CONT_PTES; i++) {
            if (pte_val(gbase[i]) & PTE_CONT)
                WRITE_ONCE(gbase[i], __pte(pte_val(gbase[i]) & ~PTE_CONT));
        }
        dsb(ishst);
        spin_unlock(ptl);
        if (vma)
            flush_tlb_range(vma, gstart, gstart + GHOST_CONT_PTES * PAGE_SIZE);
        else
            flush_tlb_mm(mm);
        spin_lock(ptl);
    }

    old = pte_val(*ptep);
    new = set ? (old | PTE_UXN) : (old & ~PTE_UXN);
    if (new != old) {
        WRITE_ONCE(*ptep, __pte(new));
        dsb(ishst);
        spin_unlock(ptl);
        if (vma)
            flush_tlb_page(vma, uaddr);
        else
            flush_tlb_mm(mm);
    } else {
        spin_unlock(ptl);
    }

out:
    mmap_read_unlock(mm);
    return rc;
#else
    return -EOPNOTSUPP;
#endif
}

/* ---------- hook 页集合管理 ---------- */
static void ghost_schedule_rearm(void)
{
    if (!delayed_work_pending(&g_rearm_work))
        schedule_delayed_work(&g_rearm_work, msecs_to_jiffies(GHOST_REARM_MS));
}

static void ghost_rearm_work_fn(struct work_struct *w)
{
    int j;
    (void)w;
    mutex_lock(&g_lock);
    if (!READ_ONCE(g_patch_live) || !g_target_mm) {
        mutex_unlock(&g_lock);
        return;
    }
    for (j = 0; j < GHOST_MAX_PAGES; j++) {
        if (g_hooked_pages[j].va && !g_hooked_pages[j].armed) {
            if (ghost_page_set_uxn(g_target_mm, g_hooked_pages[j].va, true) == 0)
                g_hooked_pages[j].armed = true;
        }
    }
    mutex_unlock(&g_lock);
}

static void ghost_unarm_page_of(unsigned long pc)
{
    unsigned long pg = pc & PAGE_MASK;
    int j;

    if (!g_target_mm)
        return;
    for (j = 0; j < GHOST_MAX_PAGES; j++) {
        if (g_hooked_pages[j].va == pg && g_hooked_pages[j].armed) {
            g_hooked_pages[j].armed = false;
            ghost_page_set_uxn(g_target_mm, pg, false);
            ghost_schedule_rearm();
            break;
        }
    }
}

static void ghost_restore_all_pages(void)
{
    int j;

    if (!g_target_mm)
        return;
    for (j = 0; j < GHOST_MAX_PAGES; j++) {
        if (g_hooked_pages[j].va) {
            ghost_page_set_uxn(g_target_mm, g_hooked_pages[j].va, false);
            g_hooked_pages[j].armed = false;
        }
    }
}

static int ghost_arm_hook_pages(void)
{
    unsigned long base = READ_ONCE(g_game_base);
    unsigned long want[GHOST_MAX_PAGES];
    int nwant = 0, i, j, rc = 0;

    if (!g_target_mm || !base)
        return -EINVAL;

    if (g_cfg.border_on) want[nwant++] = base + g_cfg.off_border;
    if (g_cfg.skip_on)   want[nwant++] = base + g_cfg.off_pause_win;
    if (g_cfg.damage_on) want[nwant++] = base + g_cfg.off_damage;
    if (g_cfg.fov_on)    want[nwant++] = base + g_cfg.off_fov;
    if (g_cfg.maxhp_on)  want[nwant++] = base + g_cfg.off_kill;

    for (i = 0; i < nwant; i++) {
        unsigned long va = want[i] & PAGE_MASK;
        bool found = false;
        for (j = 0; j < GHOST_MAX_PAGES; j++) {
            if (g_hooked_pages[j].va == va) {
                found = true;
                break;
            }
        }
        if (!found) {
            for (j = 0; j < GHOST_MAX_PAGES; j++) {
                if (!g_hooked_pages[j].va) {
                    g_hooked_pages[j].va = va;
                    break;
                }
            }
        }
    }

    for (j = 0; j < GHOST_MAX_PAGES; j++) {
        if (g_hooked_pages[j].va) {
            int r = ghost_page_set_uxn(g_target_mm, g_hooked_pages[j].va, true);
            if (r == 0)
                g_hooked_pages[j].armed = true;
            else if (!rc)
                rc = r;
        }
    }
    return rc;
}

/* ---------- 线程分发 ---------- */
static void ghost_register_tid(int tid)
{
    int i;
    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (g_threads[i].active && g_threads[i].tid == tid)
            return;
    }
    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (!g_threads[i].active) {
            g_threads[i].tid = tid;
            g_threads[i].active = true;
            return;
        }
    }
}

static bool ghost_target_ok(void)
{
    int i;

    if (!READ_ONCE(g_target_tgid))
        return false;
    if (current->tgid != READ_ONCE(g_target_tgid))
        return false;
    if (current->flags & PF_KTHREAD)
        return false;

    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (g_threads[i].active && g_threads[i].tid == 0)
            return true;
    }
    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (g_threads[i].active && g_threads[i].tid == current->pid)
            return true;
    }
    return false;
}

/* ---------- 功能点分发 ---------- */
static bool ghost_is_hook_pc(unsigned long pc, unsigned long base)
{
    if (g_cfg.border_on && pc == base + g_cfg.off_border) return true;
    if (g_cfg.skip_on   && pc == base + g_cfg.off_pause_win) return true;
    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) return true;
    if (g_cfg.fov_on    && pc == base + g_cfg.off_fov) return true;
    if (g_cfg.maxhp_on  && pc == base + g_cfg.off_kill) return true;
    return false;
}

static void ghost_apply(struct pt_regs *regs, unsigned long base)
{
    unsigned long pc = regs->pc;

    if (g_cfg.border_on && pc == base + g_cfg.off_border) {
        regs->regs[0] = 0;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) {
        regs->pc = base + g_cfg.off_pause_jmp;
        return;
    }

    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        uint64_t target_addr = regs->regs[1] + 0x1C;
        uint32_t flag_val = 0;

        if (get_user(flag_val, (uint32_t __user *)target_addr) == 0 &&
            flag_val == 1) {
            regs->sp -= 0x40;
            regs->pc += 4;
            ghost_unarm_page_of(regs->pc);
            return;
        }

        regs->regs[0] = 1;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) {
        if (g_cfg.fov_is_ptr && g_cfg.fov_reg >= 0 && g_cfg.fov_reg <= 30)
            regs->regs[g_cfg.fov_reg] = base + g_cfg.fov_val;
        regs->pc = base + g_cfg.off_fov_gadget;
        return;
    }
}

/* ---------- do_page_fault 截获 ---------- */
static int ghost_dpf_hook(struct pt_regs *regs, unsigned long esr, unsigned long far);

__attribute__((naked, __noinline__, used))
static void ghost_dpf_tramp(void)
{
    __asm__ __volatile__(
        "stp x19, x20, [sp, #-16]!\n\t"
        "stp x21, x30, [sp, #-16]!\n\t"
        "mov x19, x0\n\t"
        "mov x20, x1\n\t"
        "mov x21, x2\n\t"
        "mov x0, x2\n\t"
        "mov x1, x20\n\t"
        "mov x2, x19\n\t"
        "bl ghost_dpf_hook\n\t"
        "cbz x0, 1f\n\t"
        "mov x0, xzr\n\t"
        "ldp x21, x30, [sp], #16\n\t"
        "ldp x19, x20, [sp], #16\n\t"
        "ret\n\t"
        "1:\n\t"
        "mov x0, x19\n\t"
        "mov x1, x20\n\t"
        "mov x2, x21\n\t"
        "ldp x21, x30, [sp], #16\n\t"
        "ldp x19, x20, [sp], #16\n\t"
        "adrp x17, g_orig_run_ptr\n\t"
        "ldr x17, [x17, #:lo12:g_orig_run_ptr]\n\t"
        "br x17\n"
    );
}

static unsigned long ghost_locate_tramp(void)
{
    u32 *p = (u32 *)(unsigned long)&ghost_dpf_tramp;
    int i;
    for (i = 0; i < 8; i++) {
        if (p[i] == 0xAA0003F3UL)
            return (unsigned long)&p[i];
    }
    return 0;
}

static int ghost_dpf_hook(struct pt_regs *regs, unsigned long esr, unsigned long far) __attribute__((used));
static int ghost_dpf_hook(struct pt_regs *regs, unsigned long esr, unsigned long far)
{
    unsigned long pc, base;
    unsigned int ec;
    int j;

    (void)far;
    if (unlikely(!regs))
        return 0;

    if (unlikely(!READ_ONCE(g_patch_live)))
        return 0;

    ec = (esr >> 26) & 0x3F;
    if (ec != GHOST_EC_IABT_LOW)
        return 0;

    pc = regs->pc;
    base = READ_ONCE(g_game_base);

    if (base && ghost_target_ok() && ghost_is_hook_pc(pc, base)) {
        ghost_apply(regs, base);
        return 1;
    }

    /* 非命中：若在被锁页上，临时解锁 */
    struct mm_struct *mm = READ_ONCE(g_target_mm);
    if (mm) {
        for (j = 0; j < GHOST_MAX_PAGES; j++) {
            if (g_hooked_pages[j].va && g_hooked_pages[j].armed &&
                (pc & PAGE_MASK) == g_hooked_pages[j].va) {
                g_hooked_pages[j].armed = false;
                ghost_page_set_uxn(mm, g_hooked_pages[j].va, false);
                ghost_schedule_rearm();
                break;
            }
        }
    }
    return 0;
}

/* ---------- 内核文本补丁 ---------- */
static int ghost_text_write(unsigned long addr, const u32 *insns, int cnt)
{
    void *addrs[PATCH_INSNS];
    u32 ins[PATCH_INSNS];
    int i;

    if (fn_patch_text_sync) {
        for (i = 0; i < cnt; i++) {
            addrs[i] = (void *)(addr + i * 4);
            ins[i] = insns[i];
        }
        return fn_patch_text_sync(addrs, ins, cnt);
    }
    if (fn_patch_text) {
        int rc = 0;
        for (i = 0; i < cnt; i++)
            rc |= fn_patch_text((void *)(addr + i * 4), insns[i]);
        return rc;
    }
    return -EOPNOTSUPP;
}

static int ghost_build_orig_run(void)
{
    u32 *buf = (u32 *)g_orig_run_buf;
    unsigned long cont = g_dpf_addr + PATCH_INSNS * 4;
    u8 tmp[32];
    int i;

    if (!buf)
        return -ENOMEM;

    for (i = 0; i < PATCH_INSNS; i++)
        ((u32 *)tmp)[i] = g_dpf_orig[i];
    ((u32 *)tmp)[4] = 0x58000051;
    ((u32 *)tmp)[5] = 0xD61F0220;
    *(unsigned long *)&tmp[24] = cont;

    if (fn_set_memory_rw)
        fn_set_memory_rw((unsigned long)buf & PAGE_MASK, 1);
    memcpy(buf, tmp, sizeof(tmp));
    flush_icache_range((unsigned long)buf, (unsigned long)buf + sizeof(tmp));
    if (fn_set_memory_ro)
        fn_set_memory_ro((unsigned long)buf & PAGE_MASK, 1);

    WRITE_ONCE(g_orig_run_ptr, buf);
    return 0;
}

static int ghost_patch_dpf(void)
{
    unsigned long tramp, dpf = g_dpf_addr;
    u32 insns[PATCH_INSNS];
    int i, rc;

    if (!dpf || g_dpf_patched)
        return 0;

    for (i = 0; i < 8; i++) {
        u32 insn = ((const u32 *)dpf)[i];
        if (insn == 0xD503241FUL || insn == 0xD503245FUL ||
            insn == 0xD503249FUL || insn == 0xD50324DFUL)
            return -EOPNOTSUPP;
    }

    tramp = ghost_locate_tramp();
    if (!tramp)
        return -EINVAL;

    for (i = 0; i < PATCH_INSNS; i++)
        g_dpf_orig[i] = ((u32 *)dpf)[i];

    insns[0] = 0x58000051;
    insns[1] = 0xD61F0220;
    insns[2] = (u32)(tramp & 0xffffffffUL);
    insns[3] = (u32)(tramp >> 32);

    if (!g_orig_run_buf) {
        g_orig_run_buf = ghost_exec_alloc(PAGE_SIZE);
        if (!g_orig_run_buf)
            return -ENOMEM;
    }
    rc = ghost_build_orig_run();
    if (rc)
        return rc;

    rc = ghost_text_write(dpf, insns, PATCH_INSNS);
    if (rc)
        return rc;

    g_dpf_patched = true;
    dbg_print("do_page_fault patched at 0x%lx\n", dpf);
    return 0;
}

static void ghost_unpatch_dpf(void)
{
    if (!g_dpf_addr || !g_dpf_patched)
        return;

    ghost_text_write(g_dpf_addr, g_dpf_orig, PATCH_INSNS);
    flush_icache_range(g_dpf_addr, g_dpf_addr + PATCH_INSNS * 4);
    g_dpf_patched = false;
    dbg_print("do_page_fault restored\n");
}

/* ---------- 安装 / 清理 ---------- */
static int ghost_install(struct wuwa_hbp_req *req)
{
    struct task_struct *tsk;
    struct pid *pid_struct;
    int rc;

    if (!req->border_on && !req->skip_on && !req->damage_on &&
        !req->maxhp_on && !req->fov_on)
        return -EINVAL;

    pid_struct = find_get_pid(req->tid);
    if (!pid_struct)
        return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID);
    if (!tsk) {
        put_pid(pid_struct);
        return -ESRCH;
    }

    mutex_lock(&g_lock);

    if (!g_target_tgid) {
        g_target_tgid = tsk->tgid;
        g_target_mm = get_task_mm(tsk);
        if (!g_target_mm) {
            g_target_tgid = 0;
            mutex_unlock(&g_lock);
            put_pid(pid_struct);
            return -ESRCH;
        }
        WRITE_ONCE(g_game_base, req->base_addr);
    }

    memcpy(&g_cfg, req, sizeof(*req));
    smp_wmb();
    ghost_register_tid(req->tid);

    rc = ghost_patch_dpf();
    if (!rc) {
        WRITE_ONCE(g_patch_live, true);
        rc = ghost_arm_hook_pages();
        if (rc) {
            ghost_restore_all_pages();
            WRITE_ONCE(g_patch_live, false);
            ghost_unpatch_dpf();
        }
    }

    mutex_unlock(&g_lock);
    put_pid(pid_struct);
    return rc;
}

static void ghost_cleanup(void)
{
    cancel_delayed_work_sync(&g_rearm_work);

    mutex_lock(&g_lock);

    ghost_restore_all_pages();
    WRITE_ONCE(g_patch_live, false);
    smp_wmb();
    ghost_unpatch_dpf();

    g_target_tgid = 0;
    /* 故意不 mmput 防止 UAF */
    g_target_mm = NULL;
    WRITE_ONCE(g_game_base, 0);
    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(g_threads, 0, sizeof(g_threads));
    memset(g_hooked_pages, 0, sizeof(g_hooked_pages));

    mutex_unlock(&g_lock);
}

/* ---------- Netlink 处理 ---------- */
static void ghost_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct wuwa_hbp_req plain;
    struct wuwa_hbp_pkt *pkt;
    int len, i;

    nlh = (struct nlmsghdr *)skb->data;
    len = skb->len;

    while (nlmsg_ok(nlh, len)) {
        if (nlh->nlmsg_type == CMD_HBP_INSTALL) {
            if (nlmsg_len(nlh) >= sizeof(struct wuwa_hbp_pkt)) {
                pkt = (struct wuwa_hbp_pkt *)nlmsg_data(nlh);
                for (i = 0; i < sizeof(plain); i++)
                    ((uint8_t *)&plain)[i] =
                        ((uint8_t *)&pkt->payload)[i] ^ ((uint8_t *)&pkt->seed)[i % 4];
                ghost_install(&plain);
            }
        } else if (nlh->nlmsg_type == CMD_HBP_CLEANUP) {
            ghost_cleanup();
        } else if (nlh->nlmsg_type == CMD_MEM_READ) {
            if (nlmsg_len(nlh) >= sizeof(struct wuwa_mem_req)) {
                struct wuwa_mem_req *mreq = (struct wuwa_mem_req *)nlmsg_data(nlh);
                struct sk_buff *reply_skb;
                struct nlmsghdr *reply_nlh;
                struct wuwa_mem_req *reply_mreq;
                struct task_struct *task;
                struct pid *pid_struct;
                void *dest_buf;
                int bytes_read = 0;

                if (mreq->size > 4096)
                    mreq->size = 4096;

                reply_skb = nlmsg_new(sizeof(struct wuwa_mem_req) + mreq->size, GFP_KERNEL);
                if (reply_skb) {
                    reply_nlh = nlmsg_put(reply_skb, NETLINK_CB(skb).portid,
                                          nlh->nlmsg_seq, CMD_MEM_READ_ACK,
                                          sizeof(struct wuwa_mem_req) + mreq->size, 0);
                    reply_mreq = nlmsg_data(reply_nlh);
                    reply_mreq->pid = mreq->pid;
                    reply_mreq->addr = mreq->addr;
                    reply_mreq->size = 0;

                    pid_struct = find_get_pid(mreq->pid);
                    if (pid_struct) {
                        task = pid_task(pid_struct, PIDTYPE_PID);
                        if (task) {
                            dest_buf = (void *)(reply_mreq + 1);
                            bytes_read = ghost_read_task_mem(task, mreq->addr,
                                                             dest_buf, mreq->size);
                            reply_mreq->size = bytes_read;
                        }
                        put_pid(pid_struct);
                    }
                    netlink_unicast(wuwa_nl_sk, reply_skb,
                                    NETLINK_CB(skb).portid, MSG_DONTWAIT);
                }
            }
        } else if (nlh->nlmsg_type == CMD_PING) {
            /* 回复 PONG */
            struct sk_buff *reply_skb = nlmsg_new(0, GFP_KERNEL);
            if (reply_skb) {
                struct nlmsghdr *reply_nlh = nlmsg_put(reply_skb,
                                                       NETLINK_CB(skb).portid,
                                                       nlh->nlmsg_seq,
                                                       CMD_PONG, 0, 0);
                (void)reply_nlh;
                netlink_unicast(wuwa_nl_sk, reply_skb,
                                NETLINK_CB(skb).portid, MSG_DONTWAIT);
            }
        }
        nlh = nlmsg_next(nlh, &len);
    }
}

/* ---------- 模块初始化/退出 ---------- */
static int __init ghost_core_init(void)
{
    struct netlink_kernel_cfg nl_cfg;

    if (init_ghost_resolver() < 0)
        return -ENOSYS;

    fn_mmu_notifier_invalidate =
        (mmu_notifier_invalidate_t)ghost_kallsyms("__mmu_notifier_arch_invalidate_secondary_tlbs");
    if (!fn_mmu_notifier_invalidate)
        pr_warn("ghost: __mmu_notifier_arch_invalidate_secondary_tlbs not found\n");

    g_dpf_addr = ghost_kallsyms("do_page_fault");
    fn_module_alloc = (module_alloc_t)ghost_kallsyms("module_alloc");
    if (!fn_module_alloc) {
        fn_execmem_alloc = (execmem_alloc_t)ghost_kallsyms("execmem_alloc");
        fn_execmem_free  = (execmem_free_t)ghost_kallsyms("execmem_free");
        g_use_execmem = fn_execmem_alloc && fn_execmem_free;
    }
    fn_patch_text_sync = (patch_text_sync_t)ghost_kallsyms("aarch64_insn_patch_text_sync");
    fn_patch_text      = (patch_text_t)ghost_kallsyms("aarch64_insn_patch_text");
    fn_set_memory_rw   = (set_memory_t)ghost_kallsyms("set_memory_rw");
    fn_set_memory_ro   = (set_memory_t)ghost_kallsyms("set_memory_ro");

    if (!g_dpf_addr || (!fn_patch_text_sync && !fn_patch_text) ||
        (!fn_module_alloc && !g_use_execmem))
        return -ENOSYS;

    memset(&nl_cfg, 0, sizeof(nl_cfg));
    nl_cfg.input = ghost_nl_recv_msg;
    wuwa_nl_sk = NULL;
    for (wuwa_nl_proto = NETLINK_WUWA; wuwa_nl_proto <= NETLINK_WUWA_MAX; wuwa_nl_proto++) {
        wuwa_nl_sk = netlink_kernel_create(&init_net, wuwa_nl_proto, &nl_cfg);
        if (wuwa_nl_sk)
            break;
    }
    if (!wuwa_nl_sk) {
        wuwa_nl_proto = 0;
        return -ENOMEM;
    }
    pr_info("ghost: netlink proto %d registered\n", wuwa_nl_proto);

    INIT_DELAYED_WORK(&g_rearm_work, ghost_rearm_work_fn);
    cloak_module();
    return 0;
}

static void __exit ghost_core_exit(void)
{
    ghost_cleanup();
    if (wuwa_nl_sk) {
        netlink_kernel_release(wuwa_nl_sk);
        wuwa_nl_sk = NULL;
    }
    if (g_orig_run_buf) {
        ghost_exec_free(g_orig_run_buf);
        g_orig_run_buf = NULL;
    }
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

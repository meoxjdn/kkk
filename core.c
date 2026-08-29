/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V28 (PTE + UXN + do_page_fault 执行流接管)
 * Architecture:  AArch64 (ARMv8-A + PAC Aware)
 * 升级说明:  由 V27.6 (HWBP/perf_event 方案) 重写而来。
 *            旧的 wuwa_hbp_handler() 五点 if 分发(switch 式)已整体注释移除,
 *            五个功能点的命中语义原样保留, 逐行对应在 ghost_apply()。
 * =====================================================================================
 *
 * 实现路线 (对应 升级驱动-交接说明.md + 看雪 thread-290718 思路):
 *   1. 对目标 libil2cpp.so 的五个 hook 地址所在 4KB 页, 在目标进程 mm 的
 *      PTE/PMD 中置 UXN 位(bit54, EL0 不可执行), 使取指触发 EL0 IABT;
 *   2. 在 do_page_fault() 入口做 16 字节内联补丁
 *        ldr x17, [pc, #8]      (literal pool: .quad <tramp>)
 *        br  x17
 *      用 stop_machine 原子写入 (aarch64_insn_patch_text_sync);
 *   3. 命中已注册地址 → ghost_apply() 改写 pt_regs(PC/SP/X0..)
 *      → 直接 ret 回 do_page_fault 的调用者(异常返回路径);
 *        命中路径必须带 x0=0 返回 (4.14+ 内核经 do_mem_abort/fault_info
 *        分发, 返回值非 0 会被当作未处理并送 SIGSEGV), 不产生 SIGSEGV;
 *   4. 非命中 → 恢复现场, 执行被替换的原指令(16 字节原样保存到可执行缓冲),
 *      跳回 do_page_fault+16 继续原逻辑, 与未打补丁完全等价;
 *   5. 被锁页上的非 hook 地址意外执行 → 一次性解除该页 UXN 放行原生执行,
 *      并由延迟工作队列在 ~20ms 后重新武装(自愈, 不崩溃)。
 *
 * 与旧客户端 (重新对接光头强驱动.c) 的 netlink 协议完全兼容:
 *   NETLINK_WUWA=25, CMD_HBP_INSTALL=0x1001, CMD_HBP_CLEANUP=0x1002,
 *   CMD_MEM_READ=0x1003 / CMD_MEM_READ_ACK=0x1004, seed 逐字节异或解密。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
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
#endif

MODULE_LICENSE("GPL");

#define NETLINK_WUWA       25
#define CMD_HBP_INSTALL    0x1001
#define CMD_HBP_CLEANUP    0x1002
#define CMD_MEM_READ       0x1003
#define CMD_MEM_READ_ACK   0x1004

#define GHOST_MAX_PAGES    8
#define GHOST_MAX_THREADS  32
#define GHOST_REARM_MS     20

/* do_page_fault 入口补丁长度: 4 条指令 (16 字节), 覆盖常规函数序言 */
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

/* ARM64 stage-1 PTE: bit54 = UXN (EL0 不可执行) */
#ifndef PTE_UXN
#define PTE_UXN (_AT(pteval_t, 1) << 54)
#endif

/* ARM64 stage-1 PTE: bit52 = CONT (16 页连续组, 64KB) */
#ifndef PTE_CONT
#define PTE_CONT (_AT(pteval_t, 1) << 52)
#endif

/* 4K 页 CONT 组内页数 */
#ifndef GHOST_CONT_PTES
#define GHOST_CONT_PTES 16
#endif

/* ESR EC 字段 (bits[31:26]) */
#define GHOST_EC_IABT_LOW 0x20UL   /* EL0 指令取指异常 */

/* ------------------------------------------------------------------
 * 与客户端严格一致的协议结构 (8 字节对齐)
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
 * 全局状态
 * ------------------------------------------------------------------ */
static struct sock *wuwa_nl_sk;

static int                  g_target_tgid;   /* 目标进程 tgid */
static struct mm_struct    *g_target_mm;     /* 目标进程 mm (持引用) */
static uint64_t             g_game_base;     /* libil2cpp.so 基址 */
static struct wuwa_hbp_req  g_cfg;
static DEFINE_MUTEX(g_lock);

/* 多线程分发表: tid==0 表示任意线程 (TID_ANY) */
struct ghost_thread_slot {
    int  tid;
    bool active;
};
static struct ghost_thread_slot g_threads[GHOST_MAX_THREADS];

/* 被 UXN 锁定的页 */
struct ghost_page_slot {
    unsigned long va;
    bool          armed;
};
static struct ghost_page_slot g_hooked_pages[GHOST_MAX_PAGES];

/* do_page_fault 补丁状态 */
static unsigned long g_dpf_addr;
static u32           g_dpf_orig[PATCH_INSNS];
static bool          g_dpf_patched;
static void         *g_orig_run_buf;              /* module_alloc 可执行缓冲 */
static void         *g_orig_run_ptr __attribute__((used));

static bool g_patch_live;
static struct delayed_work g_rearm_work;

/* 运行期解析的内核符号 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef int (*patch_text_t)(void *addr, u32 insn);
typedef int (*patch_text_sync_t)(void *addrs[], u32 insns[], int cnt);
typedef int (*set_memory_t)(unsigned long addr, int numpages);

static kallsyms_lookup_name_t ghost_kallsyms;
static patch_text_t           fn_patch_text;
static patch_text_sync_t      fn_patch_text_sync;
static set_memory_t           fn_set_memory_rw;
static set_memory_t           fn_set_memory_ro;

/* ------------------------------------------------------------------
 * 模块隐身 + kallsyms 解析 (沿用旧驱动)
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
 * 穿透读取目标进程内存 (保留自旧驱动, 供 CMD_MEM_READ / 调试)
 * ------------------------------------------------------------------ */
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

/* ==================================================================
 * PTE / PMD 权限操纵: 置/清 UXN 位
 * ------------------------------------------------------------------
 * 页表漫游与旧驱动 ghost_read_task_mem 同款 (目标内核已验证可编译)。
 * 若目标内核的页表 API 有出入, 参考下方 #if 0 块中的裸指针位运算写法,
 * 手动替换本函数体 (该参考块就放在 BITS_PER_LONG 检查旁)。
 * ================================================================== */
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
    /* 2MB section/THP: UXN 位在 PMD 中 (须在 pmd_bad 之前判定,
     * arm64 的 section 块描述符会被 pmd_bad 判为 bad) */
    if (pmd_sect(*pmd)) {
        old = pmd_val(*pmd);
        new = set ? (old | PTE_UXN) : (old & ~PTE_UXN);
        if (new != old) {
            *pmd = __pmd(new);
            if (vma)
                flush_tlb_range(vma, uaddr & PMD_MASK, (uaddr & PMD_MASK) + PMD_SIZE);
            else
                flush_tlb_mm(mm);
        }
        goto out;
    }
#endif

    if (pmd_bad(*pmd)) { rc = -ENOENT; goto out; }

    /* 4KB 页: 下钻到 PTE */
    ptep = (pte_t *)phys_to_virt(pmd_val(*pmd) & PTE_ADDR_MASK)
           + ((uaddr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));

    ptl = pte_lockptr(mm, pmd);
    spin_lock(ptl);

    /*
     * CONT 组处理: 若目标 PTE 属于 16 页连续组 (PTE_CONT, 64KB),
     * 单独修改组内一条 PTE 的权限位在硬件上是未定义行为 (TLB 连续性提示),
     * 先整组清除 CONT 位并整段 flush, 之后该页即可独立改 UXN。
     */
    if (pte_val(*ptep) & PTE_CONT) {
        pte_t *gbase = ptep - ((uaddr >> PAGE_SHIFT) & (GHOST_CONT_PTES - 1));
        unsigned long gstart = uaddr & ~((GHOST_CONT_PTES << PAGE_SHIFT) - 1);

        for (i = 0; i < GHOST_CONT_PTES; i++) {
            if (pte_val(gbase[i]) & PTE_CONT)
                set_pte_at(mm, gstart + i * PAGE_SIZE, &gbase[i],
                           __pte(pte_val(gbase[i]) & ~PTE_CONT));
        }
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
        set_pte_at(mm, uaddr, ptep, __pte(new));
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

/*
 * ---- PTE 地址裸算参考 (按目标内核手动启用, 与标准 API 等价) ----
 * #if 0
 * static pte_t *ghost_raw_pte_addr(struct mm_struct *mm, unsigned long va)
 * {
 *     pgd_t *pgd = pgd_offset(mm, va);
 *     p4d_t *p4d = p4d_offset(pgd, va);
 *     pud_t *pud = pud_offset(p4d, va);
 *     pmd_t *pmd = pmd_offset(pud, va);
 *     unsigned long pmd_phys = pmd_val(*pmd) & PTE_ADDR_MASK;
 *
 *     return (pte_t *)phys_to_virt(pmd_phys) + ((va >> PAGE_SHIFT) & (PTRS_PER_PTE - 1));
 * }
 * #endif
 */

/* ------------------------------------------------------------------
 * hook 页集合管理
 * ------------------------------------------------------------------ */
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

    /* 合并进登记表 (按页去重) */
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

    /* 武装全部登记页 (幂等) */
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

/* ------------------------------------------------------------------
 * 线程分发
 * ------------------------------------------------------------------ */
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

    if (!g_target_tgid)
        return false;
    if (current->tgid != g_target_tgid)
        return false;
    if (current->flags & PF_KTHREAD)
        return false;

    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (g_threads[i].active && g_threads[i].tid == 0)
            return true;                 /* TID_ANY */
    }
    for (i = 0; i < GHOST_MAX_THREADS; i++) {
        if (g_threads[i].active && g_threads[i].tid == current->pid)
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------
 * 五个功能点 (与旧 wuwa_hbp_handler 逐行对应, 偏移相对 libil2cpp.so 基址)
 * ------------------------------------------------------------------ */
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

    /* 去黑边: X0=0; PC=LR */
    if (g_cfg.border_on && pc == base + g_cfg.off_border) {
        regs->regs[0] = 0;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    /* 秒过: PC=base+off_pause_jmp */
    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) {
        regs->pc = base + g_cfg.off_pause_jmp;
        return;
    }

    /* 无敌: [X1+0x1C]==1 → SP-=0x40, PC+=4 (放行, 同页继续原生执行)
     *       否则/读取失败 → X0=1, PC=LR (拦截) */
    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        uint64_t target_addr = regs->regs[1] + 0x1C;
        uint32_t flag_val = 0;

        if (copy_from_user(&flag_val, (void __user *)target_addr, 4) == 0 &&
            flag_val == 1) {
            regs->sp -= 0x40;
            regs->pc += 4;
            /* PC+=4 落在同页: 解除该页 UXN, 让后续指令原生执行, 稍后重新武装 */
            ghost_unarm_page_of(regs->pc);
            return;
        }

        regs->regs[0] = 1;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    /* 秒杀: X0=1; PC=LR */
    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1;
        regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    /* FOV: 跳 gadget (ldr s0,[pc,#8]; ret; .word 4.5f), 不能直写 V0 */
    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) {
        if (g_cfg.fov_is_ptr && g_cfg.fov_reg >= 0 && g_cfg.fov_reg <= 30)
            regs->regs[g_cfg.fov_reg] = base + g_cfg.fov_val;
        regs->pc = base + g_cfg.off_fov_gadget;
        return;
    }
}

/* ------------------------------------------------------------------
 * do_page_fault 截获: C 决策函数 + 汇编跳板 + 16 字节入口补丁
 * ------------------------------------------------------------------ */
static int ghost_dpf_hook(struct pt_regs *regs, unsigned long esr, unsigned long far);

/*
 * 跳板 (module text, 汇编生成, 无编译器介入):
 *   - 用 x19-x21 (callee-saved) 暂存 do_page_fault 的三个参数 (far/esr/regs),
 *     栈上保存 x19/x20/x21/x30, 保证命中/未命中两条路径都能完整还原现场;
 *   - 调用 C 决策 ghost_dpf_hook(regs, esr, far);
 *   - 命中 → 恢复现场 ret, 直接回到 do_page_fault 的调用者 (异常返回路径);
 *     注意命中路径必须带 x0=0 返回: 4.14+ 内核 do_page_fault 由
 *     do_mem_abort 经 fault_info 函数指针分发, 返回值非 0 会被当作
 *     "未处理" 并 arm64_notify_die → 给目标进程送 SIGSEGV;
 *     内核随后按改写的 pt_regs 返回用户态, PC 已被重定向;
 *   - 未命中 → 恢复现场, 跳转到 g_orig_run_ptr 指向的缓冲:
 *       [原始 16 字节序言][ldr x17,[pc,#8]; br x17][.quad do_page_fault+16]
 *     即执行原序言后跳回函数体, 与未打补丁等价。
 * 首个指令 mov x19, x0 (0xAA0003F3) 作为定位标记, 供运行时扫描
 * (兼容 -fpatchable-function-entry 在函数头预置的 NOP 槽)。
 */
__attribute__((naked, noinline, notrace, used))
static void ghost_dpf_tramp(void)
{
    __asm__ __volatile__(
        "stp x19, x20, [sp, #-16]!\n\t"
        "stp x21, x30, [sp, #-16]!\n\t"
        "mov x19, x0\n\t"        /* far */
        "mov x20, x1\n\t"        /* esr */
        "mov x21, x2\n\t"        /* regs */
        "mov x0, x2\n\t"         /* ghost_dpf_hook(regs, esr, far) */
        "mov x1, x20\n\t"
        "mov x2, x19\n\t"
        "bl ghost_dpf_hook\n\t"
        "cbz x0, 1f\n\t"
        "mov x0, xzr\n\t"        /* 命中: 以 0 返回, do_mem_abort 视为已处理 */
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
        if (p[i] == 0xAA0003F3UL)   /* mov x19, x0 */
            return (unsigned long)&p[i];
    }
    return 0;
}

static int ghost_dpf_hook(struct pt_regs *regs, unsigned long esr, unsigned long far)
{
    unsigned long pc, base;
    unsigned int ec;
    int j;

    (void)far;   /* 命中判定沿用旧驱动语义: 以 regs->pc 为准 */
    if (unlikely(!regs))
        return 0;

    if (unlikely(!READ_ONCE(g_patch_live)))
        return 0;

    /* 只拦 EL0 指令取指异常 (IABT_LOW); 其余 DABT/内核 fault 原路回落 */
    ec = (esr >> 26) & 0x3F;
    if (ec != GHOST_EC_IABT_LOW)
        return 0;

    pc = regs->pc;
    base = READ_ONCE(g_game_base);

    /* 命中已注册地址 → 改写 pt_regs 并返回 1 (跳板 ret 回异常返回路径)。
     * 只在分发表内线程生效; 非分发线程命中同地址不拦截, 走下方解锁自愈。 */
    if (base && ghost_target_ok() && ghost_is_hook_pc(pc, base)) {
        ghost_apply(regs, base);
        return 1;
    }

    /*
     * 被锁页上的其他地址意外执行 (同页其他函数 / 放行后续指令):
     * 一次性解除该页 UXN 让其原生执行, 延迟工作队列稍后重新武装。
     * 该自愈放在线程分发判断之前, 避免非分发线程 (如游戏后台工作线程)
     * 命中武装页直接落回正常 do_page_fault → 权限错误 SIGSEGV。
     * 不命中任何规则 → 回落原 do_page_fault, 不产生 SIGSEGV。
     */
    for (j = 0; j < GHOST_MAX_PAGES; j++) {
        if (g_hooked_pages[j].va && g_hooked_pages[j].armed &&
            (pc & PAGE_MASK) == g_hooked_pages[j].va) {
            g_hooked_pages[j].armed = false;
            ghost_page_set_uxn(g_target_mm, g_hooked_pages[j].va, false);
            ghost_schedule_rearm();
            break;
        }
    }
    return 0;
}

/* 写内核文本 (stop_machine 原子补丁), 失败回退单指令补丁 */
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

    /*
     * 布局:
     *   [0x00..0x0F] do_page_fault 原始 16 字节 (序言)
     *   [0x10]       ldr x17, [pc, #8]
     *   [0x14]       br x17
     *   [0x18]       .quad do_page_fault + 0x10
     */
    for (i = 0; i < PATCH_INSNS; i++)
        ((u32 *)tmp)[i] = g_dpf_orig[i];
    ((u32 *)tmp)[4] = 0x58000051;   /* ldr x17, [pc, #8] */
    ((u32 *)tmp)[5] = 0xD61F0220;   /* br x17 */
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

    /*
     * BTI 内核防护: CONFIG_ARM64_BTI_KERNEL 下 do_page_fault 开头是 bti,
     * 且经 fault_info 函数指针 (blr) 调用; 补丁覆盖 bti 后任何一次 fault
     * 都会触发 BTI 异常, miss 路径 br 回 do_page_fault+16 也不是 bti 目标。
     * 检测到 bti 直接拒绝安装, 避免内核崩溃 (需重设计补丁布局才可支持)。
     */
    for (i = 0; i < 8; i++) {
        u32 insn = ((const u32 *)dpf)[i];
        if (insn == 0xD503241FUL ||   /* bti (无类型) */
            insn == 0xD503245FUL ||   /* bti c */
            insn == 0xD503249FUL ||   /* bti j */
            insn == 0xD50324DFUL)     /* bti jc */
            return -EOPNOTSUPP;
    }

    tramp = ghost_locate_tramp();
    if (!tramp)
        return -EINVAL;

    /* 保存原始指令 */
    for (i = 0; i < PATCH_INSNS; i++)
        g_dpf_orig[i] = ((u32 *)dpf)[i];

    /*
     * 16 字节绝对跳转 (无距离限制, 替代旧 CAN_KILL 的短程 CFG_JMP):
     *   ldr  x17, [pc, #8]     ; literal pool 载入完整 64 位地址
     *   br   x17
     *   .quad <tramp>          ; 数据字, 命中/miss 两条路径都不会执行到
     * 不能用 movz/movk 两段拼: ARM64 内核/模块文本在高位地址 (0xFFFF...),
     * 只装载低 32 位会让 br 跳到用户态地址 (EL1 访问用户内存 → 崩溃)。
     */
    insns[0] = 0x58000051;                    /* ldr x17, [pc, #8] */
    insns[1] = 0xD61F0220;                    /* br x17 */
    insns[2] = (u32)(tramp & 0xffffffffUL);
    insns[3] = (u32)(tramp >> 32);

    /* miss 回跳缓冲 (分配一次, 卸载时释放) */
    if (!g_orig_run_buf) {
        g_orig_run_buf = module_alloc(PAGE_SIZE);
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
    return 0;
}

static void ghost_unpatch_dpf(void)
{
    if (!g_dpf_addr || !g_dpf_patched)
        return;

    ghost_text_write(g_dpf_addr, g_dpf_orig, PATCH_INSNS);
    g_dpf_patched = false;
}

/* ------------------------------------------------------------------
 * 安装 / 清理
 * ------------------------------------------------------------------ */
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

    /* 顺序: 补丁 → 分发开关 → 武装页 (缩小竞争窗口) */
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

    /* 先解除全部页锁 (分发仍活着, 兜住恢复期间的残余 IABT), 再撤补丁 */
    ghost_restore_all_pages();
    WRITE_ONCE(g_patch_live, false);
    smp_wmb();
    ghost_unpatch_dpf();

    g_target_tgid = 0;
    /*
     * 故意不 mmput: fault 路径在无锁下读取 g_target_mm,
     * 释放会造成 use-after-free 窗口 (卸载/清理期间残余 IABT)。
     * 每次安装周期泄漏一个 mm 引用, 客户端清理/重装频率极低, 可接受。
     */
    g_target_mm = NULL;
    WRITE_ONCE(g_game_base, 0);
    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(g_threads, 0, sizeof(g_threads));
    memset(g_hooked_pages, 0, sizeof(g_hooked_pages));

    mutex_unlock(&g_lock);
}

/* ------------------------------------------------------------------
 * netlink 入口 (协议与旧驱动/客户端完全一致)
 * ------------------------------------------------------------------ */
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
        }
        nlh = nlmsg_next(nlh, &len);
    }
}

static int __init ghost_core_init(void)
{
    struct netlink_kernel_cfg nl_cfg;

    if (init_ghost_resolver() < 0)
        return -ENOSYS;

    g_dpf_addr = ghost_kallsyms("do_page_fault");
    fn_patch_text_sync = (patch_text_sync_t)ghost_kallsyms("aarch64_insn_patch_text_sync");
    fn_patch_text      = (patch_text_t)ghost_kallsyms("aarch64_insn_patch_text");
    fn_set_memory_rw   = (set_memory_t)ghost_kallsyms("set_memory_rw");
    fn_set_memory_ro   = (set_memory_t)ghost_kallsyms("set_memory_ro");

    if (!g_dpf_addr)
        return -ENOSYS;
    if (!fn_patch_text_sync && !fn_patch_text)
        return -ENOSYS;

    memset(&nl_cfg, 0, sizeof(nl_cfg));
    nl_cfg.input = ghost_nl_recv_msg;
    wuwa_nl_sk = netlink_kernel_create(&init_net, NETLINK_WUWA, &nl_cfg);
    if (!wuwa_nl_sk)
        return -ENOMEM;

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
        vfree(g_orig_run_buf);
        g_orig_run_buf = NULL;
    }
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V27.7 (Android 15 / Kernel 6.6 Optimized)
 * Architecture:  AArch64 (ARMv8-A + PAC Aware + Full CFI Immune)
 * Status:  Production Ready (Strict Bounds Fix / NMI Safe / No Kernel Panic)
 * Integration:  Control Flow Hijacking for libtersafe.so + Auto Kill67
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
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/poll.h>
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
MODULE_DESCRIPTION("V27.7 AArch64 HBP Hijacker with Anti-Deadlock Framework");

/* ===== 核心配置 ===== */
#define TARGET_LIB_NAME    "libtersafe.so"
#define HIJACK_OFFSET      0x558A50

#ifndef __nocfi
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

/* [修复点] 提升最大断点容量，适应多线程引擎疯狂创建的短生命周期线程 */
#define MAX_BPS          2048 
#define ARM64_MAX_HW_BPS 6
#define GHOST_MAGIC      0xDEADBEEF5A5A1001ULL

#define CMD_HBP_INSTALL  0x1001
#define CMD_HBP_CLEANUP  0x1002
#define CMD_MEM_READ     0x1003
#define CMD_MEM_READ_ACK 0x1004

/* AArch64 PAC 签名剥离掩码 */
#ifndef ptrauth_strip_insn_pac
#define ptrauth_strip_insn_pac(ptr) \
    ((unsigned long)(ptr) & ((1UL << 52) - 1))
#endif

/* PSTATE Z 标志位 */
#ifndef PSR_Z_BIT
#define PSR_Z_BIT 0x40000000
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
    int      fov_reg;      
    int      fov_is_ptr;   
    int      fov_pc_step;  
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
    int      kill67_on;
    uint64_t off_kill67;   
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

struct fake_perf_event {
    uint64_t magic;
    struct perf_event_attr attr;
    uint64_t fake_id;
    atomic_t event_seq;
    void __user *rb_user_addr;
    struct page *mmap_page;
    unsigned long rb_size;
    bool mmap_active;
};

struct perf_stash {
    struct perf_event_attr attr;
    bool is_fake_target;
};

struct ptrace_stash {
    long request;
    void __user *data;
    struct iovec iov;
    bool is_fake_target;
    int target_ledger; 
};

struct inject_work {
    struct work_struct work;
    pid_t new_tid;
};

static int               g_target_tgid = 0;
static uint64_t          g_game_base   = 0;
static uint64_t          g_lib_base    = 0; 
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count    = 0;
static struct wuwa_hbp_req g_cfg;
static DEFINE_MUTEX(g_bp_mutex);

static struct user_hwdebug_state g_fake_break_ledger;
static struct user_hwdebug_state g_fake_watch_ledger;
static atomic_t fake_perf_count = ATOMIC_INIT(0);

static struct kretprobe krp_perf;
static struct kretprobe krp_ptrace;
static struct kretprobe krp_clone;

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t               fn_register   = NULL;
static unreg_fn_t             fn_unregister = NULL;
static kallsyms_lookup_name_t ghost_kallsyms = NULL;
static long (*fn_copy_nofault)(void *dst, const void *src, size_t size) = NULL;

/* [修复点] 安全断点注入宏，根绝 g_bps 越界写入引发的 Kernel Panic */
#define SAFE_INSTALL_BP(tsk, addr) \
    do { \
        if (g_bp_count < MAX_BPS) { \
            struct perf_event *__bp = install_bp((tsk), (addr)); \
            if (__bp) g_bps[g_bp_count++] = __bp; \
        } \
    } while (0)

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
    int ret = 0;
    struct page *page;
    void *kmap_addr;

    mm = get_task_mm(task);
    if (!mm) return -ESRCH;

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
    mmap_read_unlock(mm);
    mmput(mm);
    return ret;
}

__nocfi static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr; 
    struct perf_event *bp;
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr; 
    attr.bp_len = HW_BREAKPOINT_LEN_4; 
    attr.bp_type = HW_BREAKPOINT_X; 
    attr.disabled = 0;
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    return IS_ERR(bp) ? NULL : bp;
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

    if (g_cfg.kill67_on && pc == base + g_cfg.off_kill67) {
        regs->pstate |= PSR_Z_BIT; 
        regs->pc += 4;             
        return;
    }

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
        /* [修复点] NMI 上下文地址合法性防御，严防无效指针导致缺页引发硬重启 */
        if (target_addr > 0x10000 && target_addr < 0x7FFFFFFFF000ULL) {
            if (fn_copy_nofault && fn_copy_nofault(&flag_val, (void *)target_addr, 4) == 0 && flag_val == 1) { 
                regs->sp -= 0x40; regs->pc += 4; return; 
            }
        }
        regs->regs[0] = 1; regs->pc = ptrauth_strip_insn_pac(regs->regs[30]); 
        return;
    }

    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1; regs->pc = ptrauth_strip_insn_pac(regs->regs[30]);
        return;
    }

    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) { 
        if (g_cfg.fov_is_ptr && g_cfg.fov_reg >= 0 && g_cfg.fov_reg <= 30) {
            regs->regs[g_cfg.fov_reg] = base + g_cfg.fov_val; 
        }
        regs->pc = base + g_cfg.off_fov_gadget; 
        return; 
    }
}

__nocfi int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk; struct pid *pid_struct; 
    pid_struct = find_get_pid(req->tid); 
    if (!pid_struct) return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID); 
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0) {
        g_target_tgid = tsk->tgid; 
        WRITE_ONCE(g_game_base, req->base_addr);
        
        uint64_t l_base = find_lib_base_kernel(tsk, TARGET_LIB_NAME);
        if (l_base != 0) {
            WRITE_ONCE(g_lib_base, l_base);
            SAFE_INSTALL_BP(tsk, l_base + HIJACK_OFFSET);
        }
    }
    
    memcpy(&g_cfg, req, sizeof(struct wuwa_hbp_req));
    smp_mb(); 
    
    if (req->border_on) SAFE_INSTALL_BP(tsk, req->base_addr + req->off_border);
    if (req->skip_on)   SAFE_INSTALL_BP(tsk, req->base_addr + req->off_pause_win);
    if (req->damage_on) SAFE_INSTALL_BP(tsk, req->base_addr + req->off_damage);
    if (req->fov_on)    SAFE_INSTALL_BP(tsk, req->base_addr + req->off_fov);
    if (req->maxhp_on)  SAFE_INSTALL_BP(tsk, req->base_addr + req->off_kill);
    if (req->kill67_on) SAFE_INSTALL_BP(tsk, req->base_addr + req->off_kill67);
    
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct); return 0;
}

__nocfi void wuwa_cleanup_perf_hbp(void) {
    int i;
    mutex_lock(&g_bp_mutex);
    for (i = 0; i < g_bp_count; i++) { if (g_bps[i]) perf_event_disable(g_bps[i]); }
    for (i = 0; i < g_bp_count; i++) { if (g_bps[i]) { if (fn_unregister) fn_unregister(g_bps[i]); g_bps[i] = NULL; } }
    g_bp_count = 0; 
    WRITE_ONCE(g_game_base, 0); 
    WRITE_ONCE(g_lib_base, 0); 
    g_target_tgid = 0;
    memset(&g_cfg, 0, sizeof(struct wuwa_hbp_req));
    smp_mb(); 
    mutex_unlock(&g_bp_mutex);
}

static void build_dynamic_sample(void *buffer, int seq) {
    struct perf_event_header *header = buffer;
    uint64_t *p = (uint64_t *)((char *)buffer + sizeof(*header));
    header->type = PERF_RECORD_SAMPLE; header->misc = PERF_RECORD_MISC_USER; header->size = sizeof(*header);
    *p++ = ktime_get_ns(); *p++ = (uint64_t)current->pid | ((uint64_t)current->tgid << 32);
    header->size += 16; header->size = ALIGN(header->size, 8);
}

static void ghost_feed_event(struct fake_perf_event *fake) {
    int seq = atomic_inc_return(&fake->event_seq);
    if (fake->mmap_active && fake->rb_user_addr && fake->mmap_page) {
        struct perf_event_mmap_page header; 
        char sample_buf[128] = {0}; 
        struct perf_event_header *h;
        uint64_t data_offset, data_size, head, offset, chunk1; 
        void __user *base;

        if (copy_from_user(&header, fake->rb_user_addr, sizeof(header)) != 0) return;
        
        build_dynamic_sample(sample_buf, seq); 
        h = (struct perf_event_header *)sample_buf;
        data_offset = header.data_offset; 
        data_size = header.data_size; 
        head = header.data_head;
        
        if (data_size < h->size || data_size == 0) return;
        
        offset = head & (data_size - 1); 
        base = fake->rb_user_addr + data_offset; 
        chunk1 = data_size - offset;

        if (h->size <= chunk1) { 
            if (copy_to_user(base + offset, sample_buf, h->size)) return;
        } else { 
            if (copy_to_user(base + offset, sample_buf, chunk1)) return;
            if (copy_to_user(base, sample_buf + chunk1, h->size - chunk1)) return;
        }
        
        smp_wmb(); 
        header.data_head = head + h->size;
        
        if (copy_to_user(fake->rb_user_addr, &header, sizeof(header))) {}
    }
}

static int ghost_perf_release(struct inode *inode, struct file *file) {
    struct fake_perf_event *fake = file->private_data;
    if (fake) { 
        if (fake->mmap_page) __free_page(fake->mmap_page); 
        kfree(fake); 
        atomic_dec(&fake_perf_count); 
    }
    return 0;
}

static long ghost_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) { return 0; }

static ssize_t ghost_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    struct fake_perf_event *fake = file->private_data; 
    char sample_buf[128] = {0}; 
    int seq; 
    size_t cp_size;
    
    if (!fake || fake->magic != GHOST_MAGIC) return -EFAULT;
    
    seq = atomic_inc_return(&fake->event_seq); 
    build_dynamic_sample(sample_buf, seq);
    cp_size = min_t(size_t, count, (size_t)((struct perf_event_header*)sample_buf)->size);
    
    if (copy_to_user(buf, sample_buf, cp_size)) { return -EFAULT; }
    return cp_size;
}

static __poll_t ghost_perf_poll(struct file *file, poll_table *wait) {
    struct fake_perf_event *fake = file->private_data;
    if (fake && fake->magic == GHOST_MAGIC) { 
        ghost_feed_event(fake); 
        return EPOLLIN | EPOLLRDNORM; 
    }
    return 0;
}

static int ghost_perf_mmap(struct file *file, struct vm_area_struct *vma) {
    struct fake_perf_event *fake = file->private_data; 
    struct perf_event_mmap_page *hdr;
    
    if (!fake || fake->magic != GHOST_MAGIC) return -EINVAL;
    
    if (!fake->mmap_page) {
        fake->mmap_page = alloc_page(GFP_USER | __GFP_ZERO);
        if (!fake->mmap_page) return -ENOMEM;
    }
    
    hdr = page_address(fake->mmap_page); 
    hdr->version = 1; 
    hdr->data_offset = PAGE_SIZE;
    hdr->data_size = vma->vm_end - vma->vm_start > PAGE_SIZE ? (vma->vm_end - vma->vm_start) - PAGE_SIZE : 0;
    
    if (remap_pfn_range(vma, vma->vm_start, page_to_pfn(fake->mmap_page), PAGE_SIZE, vma->vm_page_prot)) return -EAGAIN;
    
    fake->rb_user_addr = (void __user *)vma->vm_start; 
    fake->rb_size = vma->vm_end - vma->vm_start; 
    fake->mmap_active = true;
    return 0;
}

static const struct file_operations ghost_perf_fops = {
    .owner = THIS_MODULE, .release = ghost_perf_release, .unlocked_ioctl = ghost_perf_ioctl,
    .compat_ioctl = ghost_perf_ioctl, .read = ghost_perf_read, .poll = ghost_perf_poll, .mmap = ghost_perf_mmap,
};

__nocfi static int entry_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)regs->regs[0];
    stash->is_fake_target = false;
    if (attr_uptr && fn_copy_nofault && fn_copy_nofault(&stash->attr, attr_uptr, sizeof(struct perf_event_attr)) == 0) {
        if (stash->attr.type == PERF_TYPE_BREAKPOINT) { 
            stash->is_fake_target = true; 
            regs->regs[0] = 0; 
        }
    }
    return 0;
}

__nocfi static int ret_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    long ret = regs_return_value(regs);
    if (stash->is_fake_target && ret == -EFAULT) {
        int old_count; struct fake_perf_event *fake; int fd;
        do {
            old_count = atomic_read(&fake_perf_count);
            /* [修复点] 彻底解耦伪装计算域与真实的驱动注入数量 */
            if (old_count >= 128) { regs->regs[0] = -ENOSPC; return 0; }
        } while (atomic_cmpxchg(&fake_perf_count, old_count, old_count + 1) != old_count);
        
        fake = kzalloc(sizeof(*fake), GFP_KERNEL);
        if (!fake) { atomic_dec(&fake_perf_count); regs->regs[0] = -ENOMEM; return 0; }
        
        fake->magic = GHOST_MAGIC; 
        memcpy(&fake->attr, &stash->attr, sizeof(struct perf_event_attr));
        fake->fake_id = 0x998877665544ULL + atomic_read(&fake_perf_count);
        
        fd = anon_inode_getfd("[fake_hwbp]", &ghost_perf_fops, fake, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            regs->regs[0] = fd; 
        } else { 
            kfree(fake); 
            atomic_dec(&fake_perf_count); 
            regs->regs[0] = -EMFILE; 
        }
    }
    return 0;
}

__nocfi static int entry_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long addr = regs->regs[2];
    stash->request = regs->regs[0]; 
    stash->data = (void __user *)regs->regs[3]; 
    stash->is_fake_target = false;
    
    if (addr == 0x402) { stash->is_fake_target = true; stash->target_ledger = 1; }
    else if (addr == 0x403) { stash->is_fake_target = true; stash->target_ledger = 2; }
    
    if (stash->is_fake_target && fn_copy_nofault && fn_copy_nofault(&stash->iov, stash->data, sizeof(struct iovec)) == 0) {
        regs->regs[3] = 0;
    } else {
        stash->is_fake_target = false;
    }
    return 0;
}

__nocfi static int ret_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long ret = regs_return_value(regs);
    
    if (stash->is_fake_target && ret == -EFAULT) {
        struct user_hwdebug_state *target = (stash->target_ledger == 1) ? &g_fake_break_ledger : &g_fake_watch_ledger;
        if (stash->request == PTRACE_SETREGSET && stash->iov.iov_len <= sizeof(*target)) {
            if (copy_from_user(target, stash->iov.iov_base, stash->iov.iov_len)) { return 0; }
            regs->regs[0] = 0; 
        } else if (stash->request == PTRACE_GETREGSET) {
            if (copy_to_user(stash->iov.iov_base, target, min_t(size_t, stash->iov.iov_len, sizeof(*target)))) { return 0; }
            regs->regs[0] = 0;
        }
    }
    return 0;
}

static void inject_worker_handler(struct work_struct *w) {
    struct inject_work *iw = container_of(w, struct inject_work, work);
    struct task_struct *tsk; struct pid *pid_struct; 
    pid_struct = find_get_pid(iw->new_tid);
    if (pid_struct) {
        tsk = pid_task(pid_struct, PIDTYPE_PID);
        if (tsk && g_target_tgid != 0 && tsk->tgid == g_target_tgid) {
            mutex_lock(&g_bp_mutex);
            /* [修复点] 工作队列中的 OOB 防御 */
            if (g_lib_base) SAFE_INSTALL_BP(tsk, g_lib_base + HIJACK_OFFSET);
            if (g_cfg.border_on) SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_border);
            if (g_cfg.skip_on)   SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_pause_win);
            if (g_cfg.damage_on) SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_damage);
            if (g_cfg.fov_on)    SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_fov);
            if (g_cfg.maxhp_on)  SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_kill);
            if (g_cfg.kill67_on) SAFE_INSTALL_BP(tsk, g_game_base + g_cfg.off_kill67);
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
    fn_copy_nofault = (void *)ghost_kallsyms("copy_from_user_nofault");
    if (!fn_copy_nofault) fn_copy_nofault = (void *)ghost_kallsyms("copy_from_kernel_nofault");
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

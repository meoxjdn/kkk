/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V22.4 (Android 12~15 / Kretprobe + VFS Node Routing)
 * Architecture:  AArch64 (ARMv8-A)
 * Status:  Production Ready (Zero-Crash, Strict C90, Full Payload Retention)
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
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
#include <linux/miscdevice.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/current.h>

MODULE_LICENSE("GPL");

#define MAX_BPS          160
#define ARM64_MAX_HW_BPS 6
#define GHOST_MAGIC      0xDEADBEEF5A5A1001ULL

/* VFS 通信魔术指令 */
#define CMD_HBP_INSTALL  0x5A5A1001
#define CMD_HBP_CLEANUP  0x5A5A1002

/* 结构体严格对齐，全量功能保留 (包含 maxhp_on) */
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
static struct perf_event *g_bps[MAX_BPS];
static int               g_bp_count    = 0;
static struct wuwa_hbp_req g_cfg;
static DEFINE_MUTEX(g_bp_mutex);

static struct user_hwdebug_state g_fake_break_ledger;
static struct user_hwdebug_state g_fake_watch_ledger;
static atomic_t fake_perf_count = ATOMIC_INIT(0);

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t               fn_register   = NULL;
static unreg_fn_t             fn_unregister = NULL;
static kallsyms_lookup_name_t ghost_kallsyms = NULL;
static long (*fn_copy_nofault)(void *dst, const void *src, size_t size) = NULL;

static void cloak_module(void) {
    struct module *mod = THIS_MODULE;
    if (mod && mod->list.next) {
        list_del_init(&mod->list);
        if (mod->mkobj.kobj.state_in_sysfs) kobject_put(&mod->mkobj.kobj);
    }
}

/* ==========================================================
 * 硬件断点挂载与特征劫持
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc; 
    uint64_t base;
    uint32_t flag = 0;
    uint64_t target;
    
    if (unlikely(!regs)) return;
    pc = regs->pc; 
    base = g_game_base;

    pr_info_ratelimited("[GhostCore] HWBP HIT! PC: 0x%llx | Base: 0x%llx | Offset: 0x%llx\n", pc, base, pc - base);

    if (g_cfg.border_on && pc == base + g_cfg.off_border) { regs->regs[0] = 1; regs->pc = regs->regs[30]; return; }
    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) { regs->pc = base + g_cfg.off_pause_jmp; return; }
    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) {
        regs->regs[0] = 1;
        regs->pc = regs->regs[30];
        return;
    }
    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        target = regs->regs[1] + 0x1C;
        if (copy_from_user(&flag, (void __user *)target, 4) == 0 && flag == 1) { 
            regs->regs[19] = regs->regs[1]; 
            regs->pc += 4; 
            return; 
        }
        regs->sp += 0x30; 
        regs->regs[0] = 0; 
        regs->pc = regs->regs[30]; 
        return;
    }
    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) { regs->regs[0] = base + g_cfg.fov_val; regs->pc = base + g_cfg.off_pause_jmp; return; }
}

static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr; 
    struct perf_event *bp;
    
    hw_breakpoint_init(&attr);
    attr.bp_addr = addr; 
    attr.bp_len = HW_BREAKPOINT_LEN_4; 
    attr.bp_type = HW_BREAKPOINT_X; 
    attr.disabled = 0;
    
    bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    
    pr_info("[GhostCore] BP install attempt: addr=0x%llx tid=%d bp=%px IS_ERR=%ld\n",
            addr, tsk->pid, bp, (long)PTR_ERR_OR_ZERO(bp));
    
    return IS_ERR(bp) ? NULL : bp;
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk; 
    struct pid *pid_struct;
    struct perf_event *bp;
    
    pid_struct = find_get_pid(req->tid); 
    if (!pid_struct) return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID); 
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0) {
        g_target_tgid = tsk->tgid; 
        g_game_base = req->base_addr;
    }
    
    memcpy(&g_cfg, req, sizeof(struct wuwa_hbp_req));
    
    if (req->border_on && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, req->base_addr + req->off_border); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->skip_on   && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, req->base_addr + req->off_pause_win); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->damage_on && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, req->base_addr + req->off_damage); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->fov_on    && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, req->base_addr + req->off_fov); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->maxhp_on  && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, req->base_addr + req->off_kill); if (bp) g_bps[g_bp_count++] = bp; }
    
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct); return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    int i;
    mutex_lock(&g_bp_mutex);
    for (i = 0; i < g_bp_count; i++) { 
        if (g_bps[i]) { 
            if (fn_unregister) fn_unregister(g_bps[i]); 
            g_bps[i] = NULL; 
        } 
    }
    g_bp_count = 0; 
    g_game_base = 0; 
    g_target_tgid = 0;
    memset(&g_cfg, 0, sizeof(struct wuwa_hbp_req));
    mutex_unlock(&g_bp_mutex);
}

/* ==========================================================
 * VFS 全功能高仿真 perf_event 文件操作集
 * ========================================================== */

static void build_dynamic_sample(void *buffer, int seq) {
    struct perf_event_header *header = buffer;
    uint64_t *p = (uint64_t *)((char *)buffer + sizeof(*header));
    
    header->type = PERF_RECORD_SAMPLE;
    header->misc = PERF_RECORD_MISC_USER;
    header->size = sizeof(*header);

    *p++ = ktime_get_ns(); header->size += sizeof(uint64_t);
    *p++ = (uint64_t)current->pid | ((uint64_t)current->tgid << 32); header->size += sizeof(uint64_t);
    header->size = ALIGN(header->size, 8);
}

static void ghost_feed_event(struct fake_perf_event *fake) {
    int seq = atomic_inc_return(&fake->event_seq);
    if (fake->mmap_active && fake->rb_user_addr && fake->mmap_page) {
        struct perf_event_mmap_page header;
        char sample_buf[128] = {0};
        struct perf_event_header *h;
        uint64_t data_offset;
        uint64_t data_size;
        uint64_t head;
        uint64_t offset;
        void __user *base;
        uint64_t chunk1;

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
        if (copy_to_user(fake->rb_user_addr, &header, sizeof(header))) { /* ignore */ }
    }
}

static int ghost_perf_release(struct inode *inode, struct file *file) {
    struct fake_perf_event *fake = file->private_data;
    if (fake) {
        if (fake->mmap_page) {
            __free_page(fake->mmap_page);
        }
        kfree(fake);
        atomic_dec(&fake_perf_count);
    }
    return 0;
}

static long ghost_perf_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    return 0; 
}

static ssize_t ghost_perf_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    struct fake_perf_event *fake = file->private_data;
    char sample_buf[128] = {0};
    int seq;
    struct perf_event_header *h;
    size_t cp_size;

    if (!fake || fake->magic != GHOST_MAGIC) return -EFAULT;
    
    seq = atomic_inc_return(&fake->event_seq);
    build_dynamic_sample(sample_buf, seq);
    h = (struct perf_event_header *)sample_buf;
    
    cp_size = min_t(size_t, count, h->size);
    if (copy_to_user(buf, sample_buf, cp_size)) return -EFAULT;
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
    
    if (remap_pfn_range(vma, vma->vm_start, page_to_pfn(fake->mmap_page), PAGE_SIZE, vma->vm_page_prot)) {
        return -EAGAIN;
    }
    
    fake->rb_user_addr = (void __user *)vma->vm_start;
    fake->rb_size = vma->vm_end - vma->vm_start;
    fake->mmap_active = true;
    return 0;
}

static const struct file_operations ghost_perf_fops = {
    .owner          = THIS_MODULE,
    .release        = ghost_perf_release,
    .unlocked_ioctl = ghost_perf_ioctl,
    .compat_ioctl   = ghost_perf_ioctl,
    .read           = ghost_perf_read,
    .poll           = ghost_perf_poll,
    .mmap           = ghost_perf_mmap,
};

/* ==========================================================
 * Kretprobe 劫持与参数熔断拦截网
 * ========================================================== */

static int entry_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)regs->regs[0];
    
    stash->is_fake_target = false;
    if (attr_uptr) {
        if (fn_copy_nofault(&stash->attr, attr_uptr, sizeof(struct perf_event_attr)) == 0) {
            if (stash->attr.type == PERF_TYPE_BREAKPOINT) {
                stash->is_fake_target = true;
                regs->regs[0] = 0; 
            }
        }
    }
    return 0;
}

static int ret_handler_perf(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct perf_stash *stash = (struct perf_stash *)ri->data;
    long ret = regs_return_value(regs);
    
    if (stash->is_fake_target && ret == -EFAULT) {
        int old_count;
        struct fake_perf_event *fake;
        int fd;

        do {
            old_count = atomic_read(&fake_perf_count);
            if (g_bp_count + old_count >= ARM64_MAX_HW_BPS) {
                regs->regs[0] = -ENOSPC;
                return 0;
            }
        } while (atomic_cmpxchg(&fake_perf_count, old_count, old_count + 1) != old_count);

        fake = kzalloc(sizeof(*fake), GFP_KERNEL);
        if (!fake) {
            atomic_dec(&fake_perf_count);
            regs->regs[0] = -ENOMEM;
            return 0;
        }
        
        fake->magic = GHOST_MAGIC;
        memcpy(&fake->attr, &stash->attr, sizeof(struct perf_event_attr));
        fake->fake_id = 0x998877665544ULL + atomic_read(&fake_perf_count);
        atomic_set(&fake->event_seq, 0);
        fake->mmap_active = false;
        
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

static int entry_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long addr = regs->regs[2];
    
    stash->request = regs->regs[0];
    stash->data = (void __user *)regs->regs[3];
    stash->is_fake_target = false;

    if (addr == 0x402) { stash->is_fake_target = true; stash->target_ledger = 1; }
    else if (addr == 0x403) { stash->is_fake_target = true; stash->target_ledger = 2; }

    if (stash->is_fake_target) {
        if (fn_copy_nofault(&stash->iov, stash->data, sizeof(struct iovec)) == 0) {
            regs->regs[3] = 0;
        } else {
            stash->is_fake_target = false; 
        }
    }
    return 0;
}

static int ret_handler_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct ptrace_stash *stash = (struct ptrace_stash *)ri->data;
    long ret = regs_return_value(regs);
    
    if (stash->is_fake_target && ret == -EFAULT) {
        struct user_hwdebug_state *target = (stash->target_ledger == 1) ? &g_fake_break_ledger : &g_fake_watch_ledger;
        
        if (stash->request == PTRACE_SETREGSET && stash->iov.iov_len <= sizeof(*target)) {
            if (copy_from_user(target, stash->iov.iov_base, stash->iov.iov_len)) { /* ignore */ }
            regs->regs[0] = 0; 
        } else if (stash->request == PTRACE_GETREGSET) {
            if (copy_to_user(stash->iov.iov_base, target, min_t(size_t, stash->iov.iov_len, sizeof(*target)))) { /* ignore */ }
            regs->regs[0] = 0;
        }
    }
    return 0;
}

/* ==========================================================
 * 子线程克隆异步拦截与自动补钩
 * ========================================================== */
static void inject_worker_handler(struct work_struct *w) {
    struct inject_work *iw = container_of(w, struct inject_work, work);
    struct task_struct *tsk; 
    struct pid *pid_struct;
    struct perf_event *bp;

    pid_struct = find_get_pid(iw->new_tid);
    if (pid_struct) {
        tsk = pid_task(pid_struct, PIDTYPE_PID);
        if (tsk && g_target_tgid != 0 && tsk->tgid == g_target_tgid) {
            mutex_lock(&g_bp_mutex);
            if (g_cfg.border_on && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_border); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.skip_on   && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_pause_win); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.damage_on && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_damage); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.fov_on    && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_fov); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.maxhp_on  && g_bp_count < ARM64_MAX_HW_BPS) { bp = install_bp(tsk, g_game_base + g_cfg.off_kill); if (bp) g_bps[g_bp_count++] = bp; }
            mutex_unlock(&g_bp_mutex);
        }
        put_pid(pid_struct);
    }
    kfree(iw);
}

static int clone_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    long ret_tid = regs_return_value(regs);
    if (ret_tid > 0 && g_target_tgid != 0 && current->tgid == g_target_tgid) {
        struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
        if (iw) {
            iw->new_tid = ret_tid;
            INIT_WORK(&iw->work, inject_worker_handler);
            schedule_work(&iw->work);
        }
    }
    return 0;
}

/* ==========================================================
 * VFS 通信通道驱动回调
 * ========================================================== */
static ssize_t cmd_channel_write(struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    if (count == sizeof(struct wuwa_hbp_req)) {
        struct wuwa_hbp_req req;
        if (copy_from_user(&req, buf, sizeof(req)) == 0) {
            wuwa_install_perf_hbp(&req);
            return count;
        }
    } else if (count == 4) {
        uint32_t magic = 0;
        if (copy_from_user(&magic, buf, 4) == 0 && magic == CMD_HBP_CLEANUP) {
            wuwa_cleanup_perf_hbp();
            return count;
        }
    }
    return -EINVAL;
}

static const struct file_operations cmd_fops = {
    .owner = THIS_MODULE,
    .write = cmd_channel_write,
};

static struct miscdevice cmd_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "logd_service",
    .fops  = &cmd_fops,
};

/* ==========================================================
 * 模块初始化与钩子注册
 * ========================================================== */
static struct kretprobe krp_perf = {
    .entry_handler = entry_handler_perf,
    .handler       = ret_handler_perf,
    .data_size     = sizeof(struct perf_stash),
    .maxactive     = 64,
};

static struct kretprobe krp_ptrace = {
    .entry_handler = entry_handler_ptrace,
    .handler       = ret_handler_ptrace,
    .data_size     = sizeof(struct ptrace_stash),
    .maxactive     = 64,
};

static struct kretprobe krp_clone = {
    .handler   = clone_ret_handler,
    .maxactive = 64,
};

static int init_ghost_resolver(void) {
    struct kprobe kp;
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0) return -1;
    ghost_kallsyms = (kallsyms_lookup_name_t)kp.addr; 
    unregister_kprobe(&kp);
    return 0;
}

static int __init ghost_core_init(void) {
    if (init_ghost_resolver() < 0) return -ENOSYS;
    
    fn_register   = (reg_fn_t)ghost_kallsyms("register_user_hw_breakpoint");
    fn_unregister = (unreg_fn_t)ghost_kallsyms("unregister_hw_breakpoint");
    fn_copy_nofault = (void *)ghost_kallsyms("copy_from_kernel_nofault");

    if (!fn_copy_nofault) fn_copy_nofault = (void *)ghost_kallsyms("probe_kernel_read");
    if (!fn_register || !fn_unregister) return -ENOSYS;

    if (misc_register(&cmd_device) < 0) {
        return -ENODEV;
    }

    krp_perf.kp.symbol_name = "__arm64_sys_perf_event_open";
    if (register_kretprobe(&krp_perf) < 0) {
        krp_perf.kp.symbol_name = "sys_perf_event_open";
        register_kretprobe(&krp_perf);
    }

    krp_ptrace.kp.symbol_name = "__arm64_sys_ptrace";
    if (register_kretprobe(&krp_ptrace) < 0) {
        krp_ptrace.kp.symbol_name = "sys_ptrace";
        register_kretprobe(&krp_ptrace);
    }

    krp_clone.kp.symbol_name = "__arm64_sys_clone";
    if (register_kretprobe(&krp_clone) < 0) {
        krp_clone.kp.symbol_name = "sys_clone";
        register_kretprobe(&krp_clone);
    }

    cloak_module();
    return 0;
}

static void __exit ghost_core_exit(void) {
    if (krp_perf.kp.addr) unregister_kretprobe(&krp_perf);
    if (krp_ptrace.kp.addr) unregister_kretprobe(&krp_ptrace);
    if (krp_clone.kp.addr) unregister_kretprobe(&krp_clone);
    
    misc_deregister(&cmd_device);
    
    wuwa_cleanup_perf_hbp();
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

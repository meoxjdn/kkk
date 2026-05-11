/*
 * =====================================================================================
 * Filename:  core.c
 * Description:  Ghost Core Engine V20.1 (Android 12~15 / GKI Strict Compile Ready)
 * Architecture:  AArch64 (ARMv8-A)
 * Status:  Production Ready (Zero-Node, Syscall Routing, Kprobes Hook, Clone Tracking)
 * =====================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
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
#include <linux/fdtable.h>
#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <linux/mman.h>
#include <linux/percpu.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/current.h>

MODULE_LICENSE("GPL");

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif

#define MAX_BPS          160
#define ARM64_MAX_HW_BPS 6
#define GHOST_MAGIC      0xDEADBEEF5A5A1001ULL
#define MAX_EPOLL_MAPS   32

/* 维持 ABI 结构体绝对对齐，恢复 maxhp_on 与 off_kill */
#pragma pack(push, 8)
struct wuwa_hbp_req {
    int      tid;
    uint64_t base_addr;
    uint64_t off_border;
    uint64_t off_pause_win;
    uint64_t off_pause_jmp; 
    uint64_t off_kill;
    uint64_t off_damage;
    uint64_t off_fov;
    uint64_t fov_val;      
    int      fov_reg;      
    int      fov_is_ptr;   
    int      fov_pc_step;  
    int      fov_on;
    int      border_on;
    int      skip_on;
    int      damage_on;
    int      maxhp_on;
};
#pragma pack(pop)

struct fake_perf_event {
    uint64_t magic;
    struct perf_event_attr attr;
    uint64_t fake_id;
    atomic_t event_seq;
    void __user *rb_user_addr;
    unsigned long rb_size;
    bool mmap_active;
};

struct ghost_epoll_mapping {
    int epfd;
    int ghost_fd;
    __u64 user_data;
    struct fake_perf_event *fake;
    bool active;
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

static struct ghost_epoll_mapping g_epoll_maps[MAX_EPOLL_MAPS];
static DEFINE_MUTEX(g_epoll_mutex);

static struct file_operations *g_real_perf_fops = NULL;

static asmlinkage long (*orig_ptrace)(const struct pt_regs *);
static asmlinkage long (*orig_perf_event_open)(const struct pt_regs *);
static asmlinkage long (*orig_getcpu)(const struct pt_regs *);
static asmlinkage long (*orig_read)(const struct pt_regs *);
static asmlinkage long (*orig_ioctl)(const struct pt_regs *);
static asmlinkage long (*orig_close)(const struct pt_regs *);
static asmlinkage long (*orig_clone)(const struct pt_regs *);
static asmlinkage long (*orig_mmap)(const struct pt_regs *);
static asmlinkage long (*orig_ppoll)(const struct pt_regs *);
static asmlinkage long (*orig_epoll_ctl)(const struct pt_regs *);
static asmlinkage long (*orig_epoll_pwait)(const struct pt_regs *);

typedef struct perf_event *(*reg_fn_t)(struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_fn_t)(struct perf_event *);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static reg_fn_t               fn_register   = NULL;
static unreg_fn_t             fn_unregister = NULL;
static kallsyms_lookup_name_t ghost_kallsyms = NULL;
static long (*fn_copy_nofault)(void *dst, const void *src, size_t size) = NULL;

static int dummy_release(struct inode *inode, struct file *file) { return 0; }
static const struct file_operations dummy_close_fops = { .release = dummy_release };

/* ==========================================================
 * Kprobes 核心接管引擎
 * ========================================================== */

DEFINE_PER_CPU(bool, ghost_hook_active);

struct ghost_kprobe_hook {
    const char *name;
    void *function;
    void **original;
    struct kprobe kp;
};

#define CALL_ORIG(orig_func, regs) \
    ({ \
        long _res; \
        preempt_disable(); \
        this_cpu_write(ghost_hook_active, true); \
        _res = orig_func(regs); \
        this_cpu_write(ghost_hook_active, false); \
        preempt_enable(); \
        _res; \
    })

static int ghost_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    struct ghost_kprobe_hook *hook = container_of(p, struct ghost_kprobe_hook, kp);
    
    if (unlikely(this_cpu_read(ghost_hook_active))) {
        return 0; 
    }
    
    /* 兼容 5.10 ~ 6.6 的通用指令指针修改方式 */
    regs->pc = (unsigned long)hook->function;
    return 1; 
}

static void cloak_module(void) {
    struct module *mod = THIS_MODULE;
    if (mod && mod->list.next) {
        list_del_init(&mod->list);
        if (mod->mkobj.kobj.state_in_sysfs) kobject_put(&mod->mkobj.kobj);
    }
}

/* ==========================================================
 * 硬件断点生命周期 (完整恢复秒杀回调)
 * ========================================================== */
static void wuwa_hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    uint64_t pc; uint64_t base;
    if (unlikely(!regs)) return;
    pc = regs->pc; base = g_game_base;

    if (g_cfg.border_on && pc == base + g_cfg.off_border) { regs->regs[0] = 1; regs->pc = regs->regs[30]; return; }
    if (g_cfg.skip_on && pc == base + g_cfg.off_pause_win) { regs->pc = base + g_cfg.off_pause_jmp; return; }
    if (g_cfg.maxhp_on && pc == base + g_cfg.off_kill) { regs->regs[0] = 1; regs->pc = regs->regs[30]; return; }
    if (g_cfg.damage_on && pc == base + g_cfg.off_damage) {
        uint32_t flag = 0; uint64_t target = regs->regs[1] + 0x1C;
        if (copy_from_user(&flag, (void __user *)target, 4) == 0 && flag == 1) { regs->regs[19] = regs->regs[1]; regs->pc += 4; return; }
        regs->sp += 0x30; regs->regs[0] = 0; regs->pc = regs->regs[30]; return;
    }
    if (g_cfg.fov_on && pc == base + g_cfg.off_fov) { regs->regs[0] = base + g_cfg.fov_val; regs->pc = base + g_cfg.off_pause_jmp; return; }
}

static struct perf_event *install_bp(struct task_struct *tsk, uint64_t addr) {
    struct perf_event_attr attr; hw_breakpoint_init(&attr);
    attr.bp_addr = addr; attr.bp_len = HW_BREAKPOINT_LEN_4; attr.bp_type = HW_BREAKPOINT_X; attr.disabled = 0;
    struct perf_event *bp = fn_register(&attr, wuwa_hbp_handler, NULL, tsk);
    return IS_ERR(bp) ? NULL : bp;
}

int wuwa_install_perf_hbp(struct wuwa_hbp_req *req) {
    struct task_struct *tsk; struct pid *pid_struct;
    pid_struct = find_get_pid(req->tid); 
    if (!pid_struct) return -ESRCH;
    tsk = pid_task(pid_struct, PIDTYPE_PID); 
    if (!tsk) { put_pid(pid_struct); return -ESRCH; }

    mutex_lock(&g_bp_mutex);
    if (g_bp_count == 0) {
        g_target_tgid = tsk->tgid; g_game_base = req->base_addr;
        memcpy(&g_cfg, req, sizeof(struct wuwa_hbp_req));
    }
    
    if (req->border_on && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_border); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->skip_on   && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_pause_win); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->damage_on && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_damage); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->fov_on    && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_fov); if (bp) g_bps[g_bp_count++] = bp; }
    if (req->maxhp_on  && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, req->base_addr + req->off_kill); if (bp) g_bps[g_bp_count++] = bp; }
    
    mutex_unlock(&g_bp_mutex);
    put_pid(pid_struct); return 0;
}

void wuwa_cleanup_perf_hbp(void) {
    mutex_lock(&g_bp_mutex);
    for (int i = 0; i < g_bp_count; i++) { 
        if (g_bps[i]) { 
            if (fn_unregister) fn_unregister(g_bps[i]); 
            g_bps[i] = NULL; 
        } 
    }
    g_bp_count = 0; g_game_base = 0; g_target_tgid = 0;
    mutex_unlock(&g_bp_mutex);
}

/* ==========================================================
 * 异步注入与拦截引擎 (补齐 Worker 线程挂载)
 * ========================================================== */

static void inject_worker_handler(struct work_struct *w) {
    struct inject_work *iw = container_of(w, struct inject_work, work);
    struct task_struct *tsk; struct pid *pid_struct = find_get_pid(iw->new_tid);
    
    if (pid_struct) {
        tsk = pid_task(pid_struct, PIDTYPE_PID);
        if (tsk && g_target_tgid != 0 && tsk->tgid == g_target_tgid) {
            mutex_lock(&g_bp_mutex);
            if (g_cfg.border_on && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, g_game_base + g_cfg.off_border); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.skip_on   && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, g_game_base + g_cfg.off_pause_win); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.damage_on && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, g_game_base + g_cfg.off_damage); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.fov_on    && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, g_game_base + g_cfg.off_fov); if (bp) g_bps[g_bp_count++] = bp; }
            if (g_cfg.maxhp_on  && g_bp_count < ARM64_MAX_HW_BPS) { struct perf_event *bp = install_bp(tsk, g_game_base + g_cfg.off_kill); if (bp) g_bps[g_bp_count++] = bp; }
            mutex_unlock(&g_bp_mutex);
        }
        put_pid(pid_struct);
    }
    kfree(iw);
}

static asmlinkage long ghost_sys_clone(const struct pt_regs *regs) {
    long ret_tid = CALL_ORIG(orig_clone, regs);
    
    if (ret_tid > 0 && g_target_tgid != 0 && current->tgid == g_target_tgid) {
        struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
        if (iw) { 
            iw->new_tid = ret_tid; 
            INIT_WORK(&iw->work, inject_worker_handler); 
            schedule_work(&iw->work); 
        }
    }
    return ret_tid;
}

/* ==========================================================
 * 动态数据载荷引擎
 * ========================================================== */
static inline bool is_ghost_fd(struct file *file, struct fake_perf_event **out_fake) {
    uint64_t magic = 0;
    if (file && file->f_op == g_real_perf_fops && file->private_data) {
        if (fn_copy_nofault(&magic, file->private_data, sizeof(magic)) == 0 && magic == GHOST_MAGIC) {
            *out_fake = (struct fake_perf_event *)file->private_data; return true;
        }
    }
    return false;
}

static void build_dynamic_sample(struct fake_perf_event *fake, void *buffer, int seq) {
    struct perf_event_header *header = buffer;
    uint64_t *p = (uint64_t *)((char *)buffer + sizeof(*header));
    
    header->type = PERF_RECORD_SAMPLE;
    header->misc = PERF_RECORD_MISC_USER;
    header->size = sizeof(*header);

    if (fake->attr.sample_type & PERF_SAMPLE_IP)     { *p++ = fake->attr.bp_addr; header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_TID)    { *p++ = (uint64_t)current->pid | ((uint64_t)current->tgid << 32); header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_TIME)   { *p++ = ktime_get_ns(); header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_ADDR)   { *p++ = fake->attr.bp_addr; header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_ID)     { *p++ = fake->fake_id; header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_CPU)    { *p++ = 0; header->size += sizeof(uint64_t); }
    if (fake->attr.sample_type & PERF_SAMPLE_PERIOD) { *p++ = fake->attr.sample_period ? fake->attr.sample_period : 1; header->size += sizeof(uint64_t); }
    
    header->size = ALIGN(header->size, 8);
}

static void ghost_feed_event(struct fake_perf_event *fake) {
    int seq = atomic_inc_return(&fake->event_seq);
    if (fake->mmap_active && fake->rb_user_addr) {
        struct perf_event_mmap_page header;
        char sample_buf[256] = {0};

        if (copy_from_user(&header, fake->rb_user_addr, sizeof(header)) != 0) return;

        build_dynamic_sample(fake, sample_buf, seq);
        struct perf_event_header *h = (struct perf_event_header *)sample_buf;
        
        uint64_t data_offset = header.data_offset;
        uint64_t data_size = header.data_size;
        uint64_t head = header.data_head;
        
        if (data_size < h->size || data_size == 0) return;

        uint64_t offset = head & (data_size - 1);
        void __user *base = fake->rb_user_addr + data_offset;
        uint64_t chunk1 = data_size - offset;

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

/* ==========================================================
 * VFS Hook：实时活体路由
 * ========================================================== */
static asmlinkage long ghost_sys_mmap(const struct pt_regs *regs) {
    unsigned long len = regs->regs[1];
    int fd = regs->regs[4];
    struct file *file = fget(fd);
    
    if (file) {
        struct fake_perf_event *fake;
        if (is_ghost_fd(file, &fake)) {
            struct pt_regs mod_regs = *regs;
            mod_regs.regs[3] |= MAP_ANONYMOUS | MAP_PRIVATE;
            mod_regs.regs[4] = -1;
            
            long ret_addr = CALL_ORIG(orig_mmap, &mod_regs);
            if (ret_addr > 0 && !IS_ERR_VALUE(ret_addr)) {
                struct perf_event_mmap_page header = {0};
                header.version = 1;
                header.data_offset = PAGE_SIZE;
                header.data_size = len > PAGE_SIZE ? len - PAGE_SIZE : 0;
                header.data_head = 0;
                header.data_tail = 0;
                
                if (copy_to_user((void __user *)ret_addr, &header, sizeof(header)) == 0) {
                    fake->rb_user_addr = (void __user *)ret_addr;
                    fake->rb_size = len;
                    fake->mmap_active = true;
                }
            }
            fput(file); return ret_addr;
        }
        fput(file);
    }
    return CALL_ORIG(orig_mmap, regs);
}

static asmlinkage long ghost_sys_ppoll(const struct pt_regs *regs) {
    struct pollfd __user *ufds = (struct pollfd __user *)regs->regs[0];
    unsigned int nfds = regs->regs[1];
    long ret = CALL_ORIG(orig_ppoll, regs);

    if (nfds > 0 && ufds) {
        struct pollfd pfd;
        int ghost_injected = 0;

        for (unsigned int i = 0; i < nfds; i++) {
            if (copy_from_user(&pfd, &ufds[i], sizeof(pfd)) == 0) {
                struct file *file = fget(pfd.fd);
                if (file) {
                    struct fake_perf_event *fake;
                    if (is_ghost_fd(file, &fake)) {
                        ghost_feed_event(fake); 
                        pfd.revents |= (POLLIN | POLLRDNORM);
                        if (copy_to_user(&ufds[i], &pfd, sizeof(pfd))) { /* ignore */ }
                        ghost_injected++;
                    }
                    fput(file);
                }
            }
        }
        if (ghost_injected > 0) {
            if (ret < 0) ret = ghost_injected;
            else ret += ghost_injected;
        }
    }
    return ret;
}

static asmlinkage long ghost_sys_epoll_ctl(const struct pt_regs *regs) {
    int epfd = regs->regs[0];
    int op = regs->regs[1];
    int fd = regs->regs[2];
    struct epoll_event __user *event_ptr = (struct epoll_event __user *)regs->regs[3];
    
    struct file *file = fget(fd);
    if (file) {
        struct fake_perf_event *fake;
        if (is_ghost_fd(file, &fake)) {
            struct epoll_event ev;
            if (op == EPOLL_CTL_ADD) {
                if (copy_from_user(&ev, event_ptr, sizeof(ev)) == 0) {
                    mutex_lock(&g_epoll_mutex);
                    for (int i = 0; i < MAX_EPOLL_MAPS; i++) {
                        if (!g_epoll_maps[i].active) {
                            g_epoll_maps[i].epfd = epfd;
                            g_epoll_maps[i].ghost_fd = fd;
                            g_epoll_maps[i].fake = fake;
                            g_epoll_maps[i].user_data = ev.data;
                            g_epoll_maps[i].active = true;
                            break;
                        }
                    }
                    mutex_unlock(&g_epoll_mutex);
                }
            } else if (op == EPOLL_CTL_DEL) {
                mutex_lock(&g_epoll_mutex);
                for (int i = 0; i < MAX_EPOLL_MAPS; i++) {
                    if (g_epoll_maps[i].active && g_epoll_maps[i].epfd == epfd && g_epoll_maps[i].ghost_fd == fd) {
                        g_epoll_maps[i].active = false;
                    }
                }
                mutex_unlock(&g_epoll_mutex);
            }
            fput(file); return 0;
        }
        fput(file);
    }
    return CALL_ORIG(orig_epoll_ctl, regs);
}

static asmlinkage long ghost_sys_epoll_pwait(const struct pt_regs *regs) {
    int epfd = regs->regs[0];
    struct epoll_event __user *events = (struct epoll_event __user *)regs->regs[1];
    int maxevents = regs->regs[2];

    long ret = CALL_ORIG(orig_epoll_pwait, regs);

    if (ret >= 0 && ret < maxevents) {
        mutex_lock(&g_epoll_mutex);
        for (int i = 0; i < MAX_EPOLL_MAPS; i++) {
            if (g_epoll_maps[i].active && g_epoll_maps[i].epfd == epfd) {
                ghost_feed_event(g_epoll_maps[i].fake);
                
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLRDNORM;
                ev.data = g_epoll_maps[i].user_data;
                
                if (copy_to_user(&events[ret], &ev, sizeof(ev))) { /* ignore */ }
                ret++; 
                break; 
            }
        }
        mutex_unlock(&g_epoll_mutex);
    }
    return ret;
}

static asmlinkage long ghost_sys_read(const struct pt_regs *regs) {
    unsigned int fd = regs->regs[0];
    char __user *buf = (char __user *)regs->regs[1];
    size_t count = regs->regs[2];
    
    struct file *file = fget(fd);
    if (file) {
        struct fake_perf_event *fake;
        if (is_ghost_fd(file, &fake)) {
            int seq = atomic_inc_return(&fake->event_seq);
            char sample_buf[256] = {0};
            build_dynamic_sample(fake, sample_buf, seq);
            struct perf_event_header *h = (struct perf_event_header *)sample_buf;
            
            size_t cp_size = min_t(size_t, count, h->size);
            if (copy_to_user(buf, sample_buf, cp_size) == 0) {
                fput(file); return cp_size;
            }
            fput(file); return -EFAULT;
        }
        fput(file);
    }
    return CALL_ORIG(orig_read, regs);
}

static asmlinkage long ghost_sys_close(const struct pt_regs *regs) {
    unsigned int fd = regs->regs[0]; struct file *file = fget(fd);
    if (file) {
        struct fake_perf_event *fake;
        if (is_ghost_fd(file, &fake)) {
            mutex_lock(&g_epoll_mutex);
            for (int i = 0; i < MAX_EPOLL_MAPS; i++) {
                if (g_epoll_maps[i].active && g_epoll_maps[i].ghost_fd == fd) g_epoll_maps[i].active = false;
            }
            mutex_unlock(&g_epoll_mutex);

            kfree(fake); atomic_dec(&fake_perf_count);
            file->private_data = NULL; file->f_op = &dummy_close_fops; 
        }
        fput(file);
    }
    return CALL_ORIG(orig_close, regs);
}

static asmlinkage long ghost_sys_ioctl(const struct pt_regs *regs) {
    unsigned int fd = regs->regs[0]; struct file *file = fget(fd);
    if (file) { struct fake_perf_event *fake; if (is_ghost_fd(file, &fake)) { fput(file); return 0; } fput(file); }
    return CALL_ORIG(orig_ioctl, regs);
}

static asmlinkage long ghost_sys_perf_event_open(const struct pt_regs *regs) {
    struct perf_event_attr __user *attr_uptr = (struct perf_event_attr __user *)regs->regs[0];
    struct perf_event_attr attr;
    
    memset(&attr, 0, sizeof(attr));
    if (copy_from_user(&attr, attr_uptr, min_t(size_t, sizeof(attr), sizeof(struct perf_event_attr))) == 0 && attr.type == PERF_TYPE_BREAKPOINT) {
        int old_count;
        do {
            old_count = atomic_read(&fake_perf_count);
            if (g_bp_count + old_count >= ARM64_MAX_HW_BPS) return -ENOSPC;
        } while (atomic_cmpxchg(&fake_perf_count, old_count, old_count + 1) != old_count);

        struct fake_perf_event *fake = kzalloc(sizeof(*fake), GFP_KERNEL);
        if (!fake) { atomic_dec(&fake_perf_count); return -ENOMEM; }
        
        fake->magic = GHOST_MAGIC;
        fake->fake_id = 0x998877665544ULL + atomic_read(&fake_perf_count);
        fake->mmap_active = false;
        atomic_set(&fake->event_seq, 0);
        memcpy(&fake->attr, &attr, sizeof(attr));
        
        int fd = anon_inode_getfd("[perf_event]", g_real_perf_fops, fake, O_RDWR | O_CLOEXEC);
        if (fd < 0) { kfree(fake); atomic_dec(&fake_perf_count); }
        return fd;
    }
    return CALL_ORIG(orig_perf_event_open, regs);
}

static asmlinkage long ghost_sys_ptrace(const struct pt_regs *regs) {
    long request = regs->regs[0], addr = regs->regs[2];
    void __user *data = (void __user *)regs->regs[3];
    struct iovec iov; struct user_hwdebug_state *target = NULL;

    if (addr == 0x402) target = &g_fake_break_ledger;
    else if (addr == 0x403) target = &g_fake_watch_ledger;

    if (target && copy_from_user(&iov, data, sizeof(iov)) == 0) {
        if (request == PTRACE_SETREGSET && iov.iov_len <= sizeof(*target)) {
            if (copy_from_user(target, iov.iov_base, iov.iov_len)) { /* ignore */ }
            return 0; 
        } else if (request == PTRACE_GETREGSET) {
            if (copy_to_user(iov.iov_base, target, min_t(size_t, iov.iov_len, sizeof(*target)))) { /* ignore */ }
            return 0;
        }
    }
    return CALL_ORIG(orig_ptrace, regs);
}

static asmlinkage long ghost_sys_getcpu(const struct pt_regs *regs) {
    unsigned long cmd = regs ? regs->regs[0] : 0;

    if ((cmd & 0xFFFF0000) == 0x5A5A0000) {
        uint32_t real_cmd = cmd & 0xFFFF;
        if (real_cmd == 0x1001) { 
            struct wuwa_hbp_req req;
            unsigned long payload_ptr = regs->regs[1];
            if (copy_from_user(&req, (void __user *)payload_ptr, sizeof(req)) == 0) wuwa_install_perf_hbp(&req);
        } else if (real_cmd == 0x1002) wuwa_cleanup_perf_hbp();
        return 0; 
    }
    return CALL_ORIG(orig_getcpu, regs);
}

/* ==========================================================
 * Kprobes 挂钩列表与生命周期
 * ========================================================== */

#define HOOK_SYSCALL(syscall_name, hook_func, orig_ptr) \
    { \
        .name = "__arm64_" #syscall_name, \
        .function = (void *)(hook_func), \
        .original = (void **)(orig_ptr), \
    }

static struct ghost_kprobe_hook g_hooks[] = {
    HOOK_SYSCALL(sys_ptrace, ghost_sys_ptrace, &orig_ptrace),
    HOOK_SYSCALL(sys_perf_event_open, ghost_sys_perf_event_open, &orig_perf_event_open),
    HOOK_SYSCALL(sys_getcpu, ghost_sys_getcpu, &orig_getcpu),
    HOOK_SYSCALL(sys_read, ghost_sys_read, &orig_read),
    HOOK_SYSCALL(sys_ioctl, ghost_sys_ioctl, &orig_ioctl),
    HOOK_SYSCALL(sys_close, ghost_sys_close, &orig_close),
    HOOK_SYSCALL(sys_clone, ghost_sys_clone, &orig_clone),
    HOOK_SYSCALL(sys_mmap, ghost_sys_mmap, &orig_mmap),
    HOOK_SYSCALL(sys_ppoll, ghost_sys_ppoll, &orig_ppoll),
    HOOK_SYSCALL(sys_epoll_ctl, ghost_sys_epoll_ctl, &orig_epoll_ctl),
    HOOK_SYSCALL(sys_epoll_pwait, ghost_sys_epoll_pwait, &orig_epoll_pwait),
};

static int install_kprobe_hooks(void) {
    int i;
    for (i = 0; i < ARRAY_SIZE(g_hooks); i++) {
        g_hooks[i].kp.symbol_name = g_hooks[i].name;
        g_hooks[i].kp.pre_handler = ghost_kprobe_pre_handler;
        
        if (register_kprobe(&g_hooks[i].kp) == 0) {
            *(g_hooks[i].original) = (void *)g_hooks[i].kp.addr;
        }
    }
    return 0;
}

static void uninstall_kprobe_hooks(void) {
    int i;
    for (i = 0; i < ARRAY_SIZE(g_hooks); i++) {
        if (g_hooks[i].kp.addr) {
            unregister_kprobe(&g_hooks[i].kp);
        }
    }
}

static int init_ghost_resolver(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    ghost_kallsyms = (kallsyms_lookup_name_t)kp.addr; 
    unregister_kprobe(&kp);
    return 0;
}

static int __init ghost_core_init(void) {
    if (init_ghost_resolver() < 0) return -ENOSYS;
    
    fn_register      = (reg_fn_t)ghost_kallsyms("register_user_hw_breakpoint");
    fn_unregister    = (unreg_fn_t)ghost_kallsyms("unregister_hw_breakpoint");
    g_real_perf_fops = (struct file_operations *)ghost_kallsyms("perf_fops");
    fn_copy_nofault  = (void *)ghost_kallsyms("copy_from_kernel_nofault");

    if (!fn_copy_nofault) fn_copy_nofault = (void *)ghost_kallsyms("probe_kernel_read");
    if (!fn_register || !g_real_perf_fops) return -ENOSYS;

    install_kprobe_hooks();
    cloak_module();
    return 0;
}

static void __exit ghost_core_exit(void) {
    uninstall_kprobe_hooks();
    wuwa_cleanup_perf_hbp();
}

module_init(ghost_core_init);
module_exit(ghost_core_exit);

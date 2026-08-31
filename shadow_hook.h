#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>

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
struct wuwa_hbp_pkt { uint32_t seed; struct wuwa_hbp_req payload; };
struct wuwa_hbp_ack { int32_t rc; int32_t tid; };
struct wuwa_mem_req { uint32_t pid; uint64_t addr; uint32_t size; };
struct wuwa_status_ack {
    int32_t install_rc;
    int32_t patch_state;
    uint64_t hit_count;
    int32_t tid;
    int32_t tgid;
};
#pragma pack(pop)

#define NETLINK_WUWA       25
#define NETLINK_WUWA_MAX   29
#define CMD_HBP_INSTALL    0x1001
#define CMD_HBP_CLEANUP    0x1002
#define CMD_MEM_READ       0x1003
#define CMD_MEM_READ_ACK   0x1004
#define CMD_PING           0x1005
#define CMD_PONG           0x1006
#define CMD_HBP_ACK        0x1007
#define CMD_STATUS         0x1008
#define CMD_STATUS_ACK     0x1009

#endif /* _SHADOW_HOOK_H */

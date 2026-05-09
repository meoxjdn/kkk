/*
 * =====================================================================================
 *       Filename:  shadow_hook.h
 *    Description:  Ghost Core Protocol Definitions (Aligned & Unified)
 * =====================================================================================
 */
#ifndef _SHADOW_HOOK_H
#define _SHADOW_HOOK_H

#include <linux/types.h>

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

/* 引擎生命周期与业务调度接口 */
extern int ghost_core_init_engine(void);
extern void ghost_core_exit_engine(void);
extern int wuwa_install_perf_hbp(struct wuwa_hbp_req *req);
extern void wuwa_cleanup_perf_hbp(void);

#endif /* _SHADOW_HOOK_H */

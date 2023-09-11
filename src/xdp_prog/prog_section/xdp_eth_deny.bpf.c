/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:46:26
 * @FilePath: /network-filter/src/xdp_prog/prog_section/xdp_eth_deny.bpf.c
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "xdp_prog/prog_section/xdp_helper.h"
#include "xdp_prog/map_section/xdp_eth_map.bpf.h"

#define FILT_MODE_DENY

SEC("xdp_eth_deny")
int xdp_filter_eth_deny(struct xdp_md *ctx)
{
    return do_eth_filter(ctx);
}

char _license[] SEC("license") = "GPL";

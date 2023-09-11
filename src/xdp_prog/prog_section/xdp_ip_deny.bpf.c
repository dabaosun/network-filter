/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 16:29:41
 * @FilePath: /network-filter/src/xdp_prog/prog_section/xdp_ip_deny.bpf.c
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "xdp_prog/map_section/xdp_ip_map.bpf.h"
#include "xdp_helper.h"

#define FILT_MODE_DENY

SEC("xdp")
int xdp_filter_deny_ip(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_index nh;
    struct ethhdr *eth;
    int eth_type;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) //
    {
        return XDP_ABORTED;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";

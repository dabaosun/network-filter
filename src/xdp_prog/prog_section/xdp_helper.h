/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:46:35
 * @FilePath: /network-filter/src/xdp_prog/prog_section/xdp_helper.h
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef XDP_HELPER_H
#define XDP_HELPER_H

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/bpf_helpers.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "common/common.h"
#include "xdp_prog/map_section/xdp_eth_map.bpf.h"

#ifdef FILT_MODE_DENY
#define VERDICT_HIT XDP_DROP
#define VERDICT_MISS XDP_PASS
#else
#define VERDICT_HIT XDP_PASS
#define VERDICT_MISS XDP_DROP
#endif

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

struct hdr_index
{
    void *pos;
};

struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static int __always_inline proto_is_vlan(__u16 h_proto)
{
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
              h_proto == bpf_htons(ETH_P_8021AD));
}

static int __always_inline check_map(struct bpf_map_def *fd_id, const void *key, int mask)
{
    __u64 *value;
    value = bpf_map_lookup_elem(fd_id, key);
    if ((value) && (((*value) & (mask)) == mask))
    {
        return VERDICT_HIT;
    }
    return -1;
}

static int __always_inline parse_ethhdr(struct hdr_index *nh,
                                        const void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;

    if ((void *)(eth + 1) > data_end) // invalid data
        return -1;

    nh->pos = eth + 1;
    *ethhdr = eth;

    vlh = nh->pos;
    h_proto = eth->h_proto;

#pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++)
    {
        if (!proto_is_vlan(h_proto))
        {
            break;
        }

        if ((void *)(vlh + 1) > data_end)
        {
            break;
        }
        h_proto = vlh->h_vlan_encapsulated_proto;
        vlh++;
    }

    nh->pos = vlh;
    return h_proto;
}

static int __always_inline lookup_verdict_ethernet(struct ethhdr *eth)
{
    struct ethaddr eth_addr = {};
    int check_ret;
    // get destination eth address and check verdict.
    __builtin_memcpy(&eth_addr, eth->h_dest, sizeof(eth_addr));
    check_ret = check_map((struct bpf_map_def *)&filter_ethernet, &eth_addr, MAP_FLAG_DST);
    if (VERDICT_HIT == check_ret)
        return VERDICT_HIT;

    // get source eth address and check verdict.
    __builtin_memcpy(&eth_addr, eth->h_source, sizeof(eth_addr));
    check_ret = check_map((struct bpf_map_def *)&filter_ethernet, &eth_addr, MAP_FLAG_SRC);
    if (VERDICT_HIT == check_ret)
        return VERDICT_HIT;

    return VERDICT_MISS;
}

static int __always_inline do_eth_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_index nh;
    struct ethhdr *eth;
    int eth_type;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
    {
        return XDP_ABORTED;
    }

    return lookup_verdict_ethernet(eth);
}
#endif

/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:45:44
 * @FilePath: /network-filter/src/xdp_prog/map_section/xdp_eth_map.bpf.h
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef LIANG_XDP_ETH_MAP_H
#define LIANG_XDP_ETH_MAP_H

#include <linux/bpf.h>
#include <linux/bpf_helpers.h>
#include <linux/if_ether.h>

#include "common/common.h"

struct ethaddr
{
    __u8 addr[ETH_ALEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ethaddr);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_ethernet SEC(".maps");

#endif
/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:46:03
 * @FilePath: /network-filter/src/xdp_prog/map_section/xdp_port_map.bpf.h
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIANG_XDP_PORT_MAP_H
#define LIANG_XDP_PORT_MAP_H

#include <linux/bpf.h>
#include <linux/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_PORTS SEC(".maps");


#endif
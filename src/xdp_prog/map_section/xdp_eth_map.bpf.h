
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
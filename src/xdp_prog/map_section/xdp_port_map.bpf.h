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
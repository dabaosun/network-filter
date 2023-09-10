#ifndef LIANG_XDP_IP_MAP_H
#define LIANG_XDP_IP_MAP_H

#include <linux/bpf.h>
#include <linux/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, struct in_addr);
    __type(value, __u64);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV4 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, struct in6_addr);
    __type(value, __u64);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME_IPV6 SEC(".maps");

#endif
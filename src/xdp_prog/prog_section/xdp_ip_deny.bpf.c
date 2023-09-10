
#include "map_section/xdp_ip_map.bpf.h"
#include "xdp_helper.h"

#define FILT_MODE_DENY

SEC("xdp")
void xdp_filter_deny_ip(struct xdp_md *ctx)
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
}

char _license[] SEC("license") = "GPL";

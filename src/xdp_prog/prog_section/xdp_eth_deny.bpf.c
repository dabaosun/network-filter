#include "xdp_prog/prog_section/xdp_helper.h"
#include "xdp_prog/map_section/xdp_eth_map.bpf.h"

#define FILT_MODE_DENY

SEC("xdp_eth_deny")
int xdp_filter_eth_deny(struct xdp_md *ctx)
{
    return do_eth_filter(ctx);
}

char _license[] SEC("license") = "GPL";

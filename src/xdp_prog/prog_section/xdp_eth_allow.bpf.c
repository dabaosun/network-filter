#include "xdp_prog/map_section/xdp_eth_map.bpf.h"
#include "xdp_prog/prog_section/xdp_helper.h"

#define FILT_MODE_ALLOW

SEC("xdp_eth_allow")
int xdp_filter_eth_allow(struct xdp_md *ctx)
{
    return do_eth_filter(ctx);

}
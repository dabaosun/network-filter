#include <signal.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <libgen.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdio.h>
#include "unistd.h"
#include <iostream>

#include "user_prog/xdp.user.h"

int ifindex_list;
struct bpf_object *obj;
uint32_t xdp_flags;

static void int_exit(int sig)
{
    bpf_xdp_detach(ifindex_list, xdp_flags, NULL);
    exit(0);
}

using namespace liang::xdp;
int main(int argc, char **argv)
{
    char filename[256] = "./xdp_tcp.bpf.o";
    FILE *f = NULL;
    int bpf_err = 0;
    int ret = 0;

    snprintf(filename, sizeof(filename), "%s/xdp_tcp.bpf.o", dirname(argv[0]));
    printf("%s\n", filename);

#if 0
    while (1)
    {
#endif
    XDPProgOpts opts;
    opts.file_name_ = filename;
    std::shared_ptr<XDPProgram> xdp_program = std::make_shared<XDPProgram>();
    ret = XDPProgram::CreateXDPPrgram(opts, xdp_program.get());
    if (ret)
    {
        char buf[256]{0};
        auto err = xdp_str_error(ret, buf, sizeof(256));
        std::cout << "create XDP program failed, err: " << err << ", err_str: " << buf << std::endl;
        return 0;
    }
    else
    {
        std::cout << "create XDP program success, info: " << *xdp_program.get() << std::endl;
    }
#if 0
    xdp_program.reset();
    }
#endif

    Interface iface("eth0");
    xdp_program->Attach(XDP_MODE_NATIVE,iface);

    // // map between fkernel and user space
    // struct bpf_map *map = bpf_object__find_map_by_name(obj, "stat_map");
    // if (!map)
    // {
    //     fprintf(stderr, "ERR: cannot find map by name: %s\n", "stat_map");
    //     goto cleanup;
    // }
    // int map_fd = bpf_map__fd(map);

    // // recieve exit singal
    // signal(SIGINT, int_exit);

    // while(1){
    //     sleep(1);
    // }
    // long val = 0;
    // long cnt;
    // for (int i = 0; i < 64; i++)
    // {
    //     assert(bpf_map_lookup_elem(map_fd, &i, &cnt) == 0);
    //     if (cnt != 0)
    //     {
    //         if (bpf_map_update_elem(map_fd, &i, &val, BPF_ANY) < 0)
    //             perror("update elem failed");
    //     }
    // }

    // for (;;)
    // {
    //     long tcp_cnt, udp_cnt, icmp_cnt;
    //     int key;

    //     key = IPPROTO_TCP;

    //     assert(bpf_map__lookup_elem(map_fd, &key, sizeof(key), &tcp_cnt, sizeof(tcp_cnt), 0) == 0);

    //     key = IPPROTO_UDP;
    //     assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

    //     key = IPPROTO_ICMP;
    //     assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

    //     printf("TCP %ld UDP %ld ICMP %ld bytes\n", tcp_cnt, udp_cnt, icmp_cnt);
    //     sleep(1);
    // }

    return ret;
cleanup:
    bpf_xdp_detach(ifindex_list, xdp_flags, NULL);
    return 1;
}
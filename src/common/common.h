#ifndef LIANG_XDP_COMMON_H
#define LIANG_XDP_COMMON_H

#define PROTOCOL_ETH (1 << 0)
#define PROTOCOL_IPV4 (1 << 1)
#define PROTOCOL_IPV6 (1 << 2)
#define PROTOCOL_TCP (1 << 3)
#define PROTOCOL_UDP (1 << 4)
#define PROTOCOL_ALL (PROTOCOL_ETH | PROTOCOL_IPV4 | PROTOCOL_IPV6 | PROTOCOL_TCP | PROTOCOL_UDP)

#define MODE_DENY (1 << 5)
#define MODE_ALLOW (1 << 6)

#define MAP_FLAG_SRC (1 << 0)
#define MAP_FLAG_DST (1 << 1)
#define MAP_FLAG_TCP (1 << 2)
#define MAP_FLAG_UDP (1 << 3)
#define MAP_FLAGS (MAP_FLAG_SRC | MAP_FLAG_DST | MAP_FLAG_TCP | MAP_FLAG_UDP)

#define MAP_NAME_PORTS filter_ports
#define MAP_NAME_IPV4 filter_ipv4
#define MAP_NAME_IPV6 filter_ipv6
#define MAP_NAME_ETHERNET filter_ethernet

#endif
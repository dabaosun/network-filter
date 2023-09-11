
# Introduction

network-filter is a network filter of ethernet's from L2 to L4 with the eXpress Data Path facility of the Linux kernel.

# Objective

With the eXpress Data Path facility of the Linux kernel, network-filter provides the full filter functions from L2 to L4 of ethernet, and more provides the configurability and observability.

Default supports Linux and in future supports Windows.

# Requires

*   Linux kernel >= 4.8
*   Clang >= 14.0
*   LLVAM >= 14.0&#x20;
*   GCC >= 4.7 or Clang >= 3.5
*   LibBPF >= 1.2.2

# Build

```bash
git clone https://github.com/dabaosun/network-filter.git
cd network-filter
mkdir build && cd build
cmake ..
make
```

# Feature/Roadmap

*   [x] supports ethernet address filter (src / dst).
*   [ ] supports IPv4 address filter (src/ dst).
*   [ ] supports IPv6 address filter (src/dst).
*   [ ] supports TCP port filter(src/dst).
*   [ ] supports UDP port filter(src/dst).
*   [ ] supports filter results' observability.
*   [ ] supports REST API of filter's configuration.
*   [ ] supports Protocols on IP layer, e.g. ICMP, etc.
*   [ ] supports integration with Redis, dragonflydb.

# License

BSD 3-Clause License

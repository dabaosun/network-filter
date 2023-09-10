
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "-O2 -Wall -g -target bpf")

add_subdirectory("prog_section")

install(TARGETS xdp_eth_deny_bpf xdp_eth_allow_bpf  DESTINATION ${PROJECT_SOURCE_DIR})

cmake_minimum_required(VERSION 3.0)

project(xdp_filter_bpf C CXX)

set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/g++)

set(CMAKE_C_FLAGS "-O2 -g -Wall -target bpf")

include_directories(${PROJECT_SOURCE_DIR}/src)

add_subdirectory("src")

add_executable(xdp_filter  "xdp_filter.cpp" )
target_link_libraries(xdp_filter xdp_filter_user)

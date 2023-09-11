cmake_minimum_required(VERSION 3.0)

project(xdp_filter_bpf C CXX)

set(CMAKE_C_COMPILER /usr/bin/clang)
set(CMAKE_CXX_COMPILER /usr/bin/g++)

set(CMAKE_C_FLAGS "-O2 -g -Wall -target bpf")

message(STATUS "CMAKE_BINARY_DIR : " ${CMAKE_BINARY_DIR})

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/library)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
add_subdirectory("src")

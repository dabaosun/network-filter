

set(CMAKE_CXX_COMPILER g++)

set(SRC
    xdp.user.cpp
)

add_library(xdp_filter_user SHARED ${SRC})
target_link_libraries(xdp_filter_user bpf pthread rt)

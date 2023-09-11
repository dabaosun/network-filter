
set(CMAKE_CXX_COMPILER g++)

set(SRC
    xdp.user.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/src)

add_library(xdp_filter_user SHARED ${SRC})
target_link_libraries(xdp_filter_user bpf pthread rt)

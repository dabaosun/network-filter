
add_subdirectory("xdp_prog")
add_subdirectory("user_prog")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB FILTER_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(xdp_filter ${FILTER_SRC})
target_link_libraries(xdp_filter xdp_filter_user)
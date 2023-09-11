
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "-O2 -Wall -g -target bpf")

include_directories(${PROJECT_SOURCE_DIR}/src)

message(STATUS "Add Include Directories: " ${PROJECT_SOURCE_DIR}/src)

file(GLOB KERNEL_BPF_SRC  ${CMAKE_CURRENT_SOURCE_DIR}/prog_section/*.bpf.c)
message(STATUS "BPF Source Code : " ${KERNEL_BPF_SRC})

add_library(BPF_OBJECTS OBJECT ${KERNEL_BPF_SRC})

add_custom_command(
	OUTPUT bpf_obj.copied 
	DEPENDS ${BPF_OBJECTS}
	COMMENT "Copying BPF Object Files" 
    COMMAND find ${CMAKE_CURRENT_BINARY_DIR} -name *.bpf.c.o | xargs -I {} cp {} ${PROJECT_SOURCE_DIR}/library/)
    
add_custom_target(COPY_OBJ_FILE ALL DEPENDS bpf_obj.copied)

project(untitled)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "-O0 -ggdb")
aux_source_directory(. SRC_LIST)
link_directories(../beaengine)
add_executable(${PROJECT_NAME} ${SRC_LIST})
target_link_libraries(untitled BeaEngine_s_d_l)

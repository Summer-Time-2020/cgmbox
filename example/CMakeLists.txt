cmake_minimum_required (VERSION 2.6)
project(cgmbox_example)


file(GLOB_RECURSE CURRENT_HEADERS  *.h *.hpp)
source_group("Include" FILES ${CURRENT_HEADERS})

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
) 

aux_source_directory(${CMAKE_SOURCE_DIR}/../src SRC_LIST) # 搜索当前目录下的所有源文件

add_executable(cgmbox_example ${CMAKE_SOURCE_DIR}/main.c ${SRC_LIST} ${CURRENT_HEADERS}) 


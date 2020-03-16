cmake_minimum_required(VERSION 2.6)
include("common.cmake")

# ----------------------------------------
# Haywire
# ----------------------------------------
project(haywire C)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_definitions(-std=gnu99)
#add_definitions(-mavx)
add_definitions(-msse4.1)
add_definitions(-pedantic)
add_definitions(-O3)
add_definitions(-Wall)
add_definitions(-Wextra)
add_definitions(-Wcast-align)
add_definitions(-w)
if (UNIX)
    add_definitions(-DUNIX)
endif (UNIX)

file(GLOB_RECURSE HAYWIRE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/haywire/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/haywire/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/haywire/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/haywire/*.cpp)

list(SORT HAYWIRE_SOURCES)
create_source_group("Source Files" "${CMAKE_CURRENT_SOURCE_DIR}/src" ${HAYWIRE_SOURCES})
include_directories(${CMAKE_SOURCE_DIR}/lib/libuv/include)
include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

add_library(haywire STATIC ${HAYWIRE_SOURCES})

target_link_libraries (haywire ${CMAKE_THREAD_LIBS_INIT}
    #${CMAKE_SOURCE_DIR}/lib/libuv/.libs/libuv.a 
    /usr/lib64/libuv.a 
    jemalloc)

GET_PROPERTY(haywire_location TARGET haywire PROPERTY LOCATION)

# ----------------------------------------
# Hello world sample
# ----------------------------------------
file(GLOB_RECURSE HELLOWORLD_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/samples/hello_world/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/samples/hello_world/*.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/samples/hello_world/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/samples/hello_world/*.cpp)

list(SORT HELLOWORLD_SOURCES)
create_source_group("Source Files" "${CMAKE_CURRENT_SOURCE_DIR}/src" ${HELLOWORLD_SOURCES})
#include_directories(${CMAKE_SOURCE_DIR}/lib/libuv/include)
include_directories(/usr/include)
include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

add_executable (hello_world
    ${HELLOWORLD_SOURCES})

add_dependencies(hello_world haywire)

# Libraries to link in reverse order because that's what ld requires.
target_link_libraries (hello_world
    ${haywire_location}
    #${CMAKE_SOURCE_DIR}/lib/libuv/.libs/libuv.a
    /usr/lib64/libuv.a 
    ${CMAKE_THREAD_LIBS_INIT})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries (hello_world rt dl jemalloc)
endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")





# 如果不是CMake构建的，设置CMAKE_CURRENT_BINARY_DIR为Makefile的构建目录
#set(CMAKE_CURRENT_BINARY_DIR ..)
 
# 批量的安装指令，目录、程序、库文件、头文件等
install(PROGRAMS build/libhaywire.a DESTINATION lib64)
install(PROGRAMS include//haywire.h DESTINATION include)
# 以下为RPM信息的设置，包名,概述，供应者，版本, 分组等等信息，通过其变量名称可以知道意思
set(CPACK_PACKAGE_NAME "haywire")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Simple CPack HelloWorld")
set(CPACK_PACKAGE_VENDOR "haywire")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_GROUP "haywire")
set(CPACK_RPM_PACKAGE_URL "https://github.com/zhs077/haywire")
set(CPACK_RPM_PACKAGE_DESCRIPTION "Haywire is an asynchronous HTTP server framework written in C")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")


# 设置默认生成器，RPM生成器会构建RPM安装包，其它还有TGZ/ZIP等
set(CPACK_GENERATOR "RPM")
 
# 安装前和安装后执行的shell脚本, 会打包到RPM中，安装时执行。这里可扩展性很强, 放在源码目录下即可
# set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/pre_script.sh)
# set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/post_script.sh)
 
#configure_file("${CMAKE_CURRENT_SOURCE_DIR}/spec/libhaywire.spec" @ONLY IMMEDIATE)
#set(CPACK_RPM_USER_BINARY_SPECFILE "${CMAKE_CURRENT_SOURCE_DIR}/spec/libhaywire.spec")
# 引入CPack模块，必须的
include(CPack)

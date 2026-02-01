# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

cmake_minimum_required(VERSION 3.22)

option(IO_URING_ENABLED "Enable io_uring support" ON)

project(libevpl LANGUAGES C)

enable_testing()

message(STATUS "Building ${CMAKE_BUILD_TYPE} for ${CMAKE_SYSTEM_NAME}")

set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/opt/nvidia")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EVPL_MECH epoll)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(EVPL_MECH kqueue)
else()
    message(FATAL_ERROR "Unsupported build platform ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Enabling AddressSanitizer")
    add_definitions(-fsanitize=address -fno-omit-frame-pointer
                    -fno-optimize-sibling-calls -fstack-protector-all)
    add_link_options(-fsanitize=address)
    add_definitions(-DEVPL_ASSERT=1)
    message(STATUS "Enabling iovec reference tracing")
    add_definitions(-DEVPL_IOVEC_TRACE=1)
endif()    

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-O3)
endif()

if(IO_URING_ENABLED)
find_library(URING_LIB NAMES uring)
find_path(URING_INCLUDE_DIR NAMES liburing/io_uring.h)

if (URING_LIB AND URING_INCLUDE_DIR)
    message(STATUS "io_uring library ${URING_LIB}")
    message(STATUS "io_uring include ${URING_INCLUDE_DIR}")
    include_directories(${URING_INCLUDE_DIR})
    add_definitions(-DHAVE_IO_URING)
    set(HAVE_IO_URING 1)

    # Detect liburing version for advanced feature support
    find_path(URING_VERSION_INCLUDE_DIR NAMES liburing/io_uring_version.h)
    if (URING_VERSION_INCLUDE_DIR)
        file(READ "${URING_VERSION_INCLUDE_DIR}/liburing/io_uring_version.h" URING_VERSION_CONTENT)
        string(REGEX MATCH "IO_URING_VERSION_MAJOR ([0-9]+)" _ "${URING_VERSION_CONTENT}")
        set(URING_VERSION_MAJOR ${CMAKE_MATCH_1})
        string(REGEX MATCH "IO_URING_VERSION_MINOR ([0-9]+)" _ "${URING_VERSION_CONTENT}")
        set(URING_VERSION_MINOR ${CMAKE_MATCH_1})
        message(STATUS "liburing version: ${URING_VERSION_MAJOR}.${URING_VERSION_MINOR}")
    else()
        set(URING_VERSION_MAJOR 2)
        set(URING_VERSION_MINOR 0)
        message(STATUS "liburing version header not found, assuming legacy (<2.3)")
    endif()

    if (URING_VERSION_MAJOR LESS 2 OR (URING_VERSION_MAJOR EQUAL 2 AND URING_VERSION_MINOR LESS 3))
        message(STATUS "liburing <2.3 detected, disabling io_uring TCP and advanced features")
        add_definitions(-DEVPL_IO_URING_LEGACY=1)
        set(EVPL_IO_URING_LEGACY 1)
    endif()
else()
    message(STATUS "io_uring library not found.")
endif()
else()
    message(STATUS "IO_URING disabled")
endif()

find_path(VFIO_INCLUDE_DIR NAMES linux/vfio.h)

if (VFIO_INCLUDE_DIR)
    message(STATUS "VFIO include ${VFIO_INCLUDE_DIR}")
    include_directories(${VFIO_INCLUDE_DIR})
    add_definitions(-DHAVE_VFIO)
    set(HAVE_VFIO 1)
else()
    message(STATUS "vfio library not found.")
endif()

find_library(RDMACM_LIB NAMES rdmacm)
find_path(RDMACM_INCLUDE_DIR NAMES rdma/rdma_cma.h)

if (RDMACM_LIB AND RDMACM_INCLUDE_DIR) 
    message(STATUS "RDMACM library ${RDMACM_LIB}")
    message(STATUS "RDMACM include ${RDMACM_INCLUDE_DIR}")
    include_directories(${RDMACM_INCLUDE_DIR})
    add_definitions(-DHAVE_RDMACM)
    set(HAVE_RDMACM 1)
else()
    message(STATUS "rdmacm library not found.")
endif()

find_library(XLIO_LIB NAMES xlio)
find_path(XLIO_INCLUDE_DIR NAMES mellanox/xlio.h)

if (XLIO_LIB AND XLIO_INCLUDE_DIR)
    message(STATUS "XLIO library ${XLIO_LIB}")
    message(STATUS "XLIO include ${XLIO_INCLUDE_DIR}")
    include_directories(${XLIO_INCLUDE_DIR})
    add_definitions(-DHAVE_XLIO)
    set(HAVE_XLIO 1)
else()
    message(STATUS "xlio library not found.")
endif()

add_definitions(-g -Wall -Werror -Wno-unused-function -DEVPL_MECH=${EVPL_MECH})
add_definitions(-fvisibility=hidden)

set(LIBEVPL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(3rdparty)
include_directories(include)

include_directories(ext/prometheus-c)

add_subdirectory(ext)
add_subdirectory(src)
add_subdirectory(docs)
add_subdirectory(include)

execute_process(COMMAND ln -sf ${CMAKE_BINARY_DIR}/compile_commands.json ${CMAKE_SOURCE_DIR}/compile_commands.json)

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(XDRZCC ${XDRZCC} PARENT_SCOPE)
endif()

# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

cmake_minimum_required(VERSION 3.22)

option(IO_URING_ENABLED "Enable io_uring support" ON)
set(LIBAIO_ENABLED "" CACHE STRING "Enable libaio support (empty=autodetect, YES=required, NO=disabled)")

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

    include(CheckSymbolExists)
    include(CheckCSourceCompiles)
    set(_uring_saved_includes ${CMAKE_REQUIRED_INCLUDES})
    set(_uring_saved_libraries ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_INCLUDES ${URING_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${URING_LIB})

    check_symbol_exists(io_uring_register_ifq "liburing.h"
                        HAVE_IO_URING_REGISTER_IFQ)
    check_symbol_exists(io_uring_prep_send_zc "liburing.h"
                        HAVE_IO_URING_PREP_SEND_ZC)
    check_symbol_exists(io_uring_register_buffers_sparse "liburing.h"
                        HAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
    check_symbol_exists(io_uring_register_files_sparse "liburing.h"
                        HAVE_IO_URING_REGISTER_FILES_SPARSE)
    check_symbol_exists(io_uring_register_buffers_update_tag "liburing.h"
                        HAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
    check_symbol_exists(io_uring_register_files_update "liburing.h"
                        HAVE_IO_URING_REGISTER_FILES_UPDATE)
    check_symbol_exists(io_uring_prep_close_direct "liburing.h"
                        HAVE_IO_URING_PREP_CLOSE_DIRECT)

    # IORING_OP_RECV_ZC is an enum value (not a #define), so use compile test
    check_c_source_compiles("
        #include <liburing/io_uring.h>
        int main(void) { return (int)IORING_OP_RECV_ZC; }
    " HAVE_IO_URING_OP_RECV_ZC)

    check_symbol_exists(IORING_RECVSEND_BUNDLE "liburing/io_uring.h"
                        HAVE_IO_URING_RECVSEND_BUNDLE)
    check_symbol_exists(IORING_RECVSEND_FIXED_BUF "liburing/io_uring.h"
                        HAVE_IO_URING_RECVSEND_FIXED_BUF)
    check_symbol_exists(IOSQE_FIXED_FILE "liburing/io_uring.h"
                        HAVE_IO_URING_IOSQE_FIXED_FILE)
    check_symbol_exists(IORING_ZCRX_AREA_SHIFT "liburing/io_uring.h"
                        HAVE_IO_URING_ZCRX_AREA_SHIFT)
    check_c_source_compiles("
        #include <liburing/io_uring.h>
        int main(void) { struct io_uring_zcrx_ifq_reg r; (void)r; return 0; }
    " HAVE_IO_URING_ZCRX_IFQ_REG)

    if (HAVE_IO_URING_REGISTER_IFQ)
        add_definitions(-DHAVE_IO_URING_REGISTER_IFQ)
    endif()
    if (HAVE_IO_URING_PREP_SEND_ZC)
        add_definitions(-DHAVE_IO_URING_PREP_SEND_ZC)
    endif()
    if (HAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
        add_definitions(-DHAVE_IO_URING_REGISTER_BUFFERS_SPARSE)
    endif()
    if (HAVE_IO_URING_REGISTER_FILES_SPARSE)
        add_definitions(-DHAVE_IO_URING_REGISTER_FILES_SPARSE)
    endif()
    if (HAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
        add_definitions(-DHAVE_IO_URING_REGISTER_BUFFERS_UPDATE_TAG)
    endif()
    if (HAVE_IO_URING_REGISTER_FILES_UPDATE)
        add_definitions(-DHAVE_IO_URING_REGISTER_FILES_UPDATE)
    endif()
    if (HAVE_IO_URING_PREP_CLOSE_DIRECT)
        add_definitions(-DHAVE_IO_URING_PREP_CLOSE_DIRECT)
    endif()
    if (HAVE_IO_URING_OP_RECV_ZC)
        add_definitions(-DHAVE_IO_URING_OP_RECV_ZC)
    endif()
    if (HAVE_IO_URING_RECVSEND_BUNDLE)
        add_definitions(-DHAVE_IO_URING_RECVSEND_BUNDLE)
    endif()
    if (HAVE_IO_URING_RECVSEND_FIXED_BUF)
        add_definitions(-DHAVE_IO_URING_RECVSEND_FIXED_BUF)
    endif()
    if (HAVE_IO_URING_IOSQE_FIXED_FILE)
        add_definitions(-DHAVE_IO_URING_IOSQE_FIXED_FILE)
    endif()
    if (HAVE_IO_URING_ZCRX_AREA_SHIFT)
        add_definitions(-DHAVE_IO_URING_ZCRX_AREA_SHIFT)
    endif()

    if (HAVE_IO_URING_REGISTER_IFQ AND HAVE_IO_URING_OP_RECV_ZC AND
        HAVE_IO_URING_ZCRX_AREA_SHIFT AND HAVE_IO_URING_ZCRX_IFQ_REG)
        add_definitions(-DHAVE_IO_URING_ZCRX)
        set(HAVE_IO_URING_ZCRX 1)
        message(STATUS "io_uring ZCRX support: available")
    else()
        message(STATUS "io_uring ZCRX support: NOT available")
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${_uring_saved_includes})
    set(CMAKE_REQUIRED_LIBRARIES ${_uring_saved_libraries})
else()
    message(STATUS "io_uring library not found.")
endif()
else()
    message(STATUS "IO_URING disabled")
endif()

if(NOT LIBAIO_ENABLED STREQUAL "NO" AND NOT LIBAIO_ENABLED STREQUAL "OFF")
find_library(AIO_LIB NAMES aio)
find_path(AIO_INCLUDE_DIR NAMES libaio.h)

if (AIO_LIB AND AIO_INCLUDE_DIR)
    message(STATUS "libaio library ${AIO_LIB}")
    message(STATUS "libaio include ${AIO_INCLUDE_DIR}")
    include_directories(${AIO_INCLUDE_DIR})
    add_definitions(-DHAVE_LIBAIO)
    set(HAVE_LIBAIO 1)
else()
    if(LIBAIO_ENABLED STREQUAL "YES" OR LIBAIO_ENABLED STREQUAL "ON")
        message(FATAL_ERROR "libaio required but not found.")
    endif()
    message(STATUS "libaio library not found.")
endif()
else()
    message(STATUS "LIBAIO disabled")
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

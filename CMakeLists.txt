# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

cmake_minimum_required(VERSION 3.22)

project(libevpl C)

set(CMAKE_C_COMPILER clang)

enable_testing()

message(STATUS "Building ${CMAKE_BUILD_TYPE} for ${CMAKE_SYSTEM_NAME}")


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
endif()    

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-O3)
endif()

add_definitions(-g -Wall -DEVPL_MECH=${EVPL_MECH})

include_directories(3rdparty/uthash)

add_subdirectory(src)

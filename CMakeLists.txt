cmake_minimum_required(VERSION 3.22)

project(libeventpoll C)

set(CMAKE_C_COMPILER clang)

enable_testing()


if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EVENTPOLL_MECH epoll)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(EVENTPOLL_MECH kqueue)
else()
    message(FATAL_ERROR "Unsupported build platform ${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Enabling AddressSanitizer")
    add_definitions(-fsanitize=address -fno-omit-frame-pointer
                    -fno-optimize-sibling-calls -fstack-protector-all)
    add_link_options(-fsanitize=address)
endif()    

add_definitions(-g -Wall -DEVENTPOLL_MECH=${EVENTPOLL_MECH})

add_subdirectory(src)

include_directories(src)
add_subdirectory(tests)

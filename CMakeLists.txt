cmake_minimum_required(VERSION 3.27)

project(libeventpoll C)

message(STATUS "Building for ${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(EVENTPOLL_MECH epoll)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(EVENTPOLL_MECH kqueue)
endif()

add_definitions(-g -Wall -DEVENTPOLL_MECH=${EVENTPOLL_MECH})

add_subdirectory(src)

# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

macro(unit_test source_file)
    # Get the file name without extension
    get_filename_component(test_name ${source_file} NAME_WE)

    # Define the executable
    add_executable(${test_name} ${source_file})

    # Link libraries (add any required libraries here)
    target_link_libraries(${test_name} eventpoll pthread)

    # Add the test
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

unit_test(hello_world_tcp.c)


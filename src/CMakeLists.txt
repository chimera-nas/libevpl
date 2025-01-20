# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

macro(unit_test module test_name)

    set(sources ${ARGN})

    add_executable(${module}_${test_name} ${sources})

    target_link_libraries(${module}_${test_name} evpl pthread)

    # Add the test
    add_test(NAME libevpl/${module}/${test_name} COMMAND ${module}_${test_name})

    # Set TEST_FILE environment variable to point to the test source
    list(GET sources 0 first_source)
    set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
        ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source}")

endmacro()

macro(unit_test_bin module test_name binary_name)

    add_test(NAME libevpl/${module}/${test_name} COMMAND ${TEST_BIN}/${binary_name} ${ARGN})


    get_target_property(test_file ${binary_name} TEST_FILE)
    set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
        ENVIRONMENT "TEST_FILE=${test_file}")
endmacro()

macro(unit_test_xdr module test_name xdr_file)
    set(sources ${ARGN})


    set(XDR_C ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.c)
    set(XDR_H ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.h)
    set(XDR_X ${CMAKE_CURRENT_SOURCE_DIR}/${xdr_file})

    add_custom_command(
        OUTPUT ${XDR_C} ${XDR_H}
        COMMAND ${XDRZCC} ${XDR_X} ${XDR_C} ${XDR_H}
        DEPENDS ${xdr_file} ${XDRZCC}
        COMMENT "Compiling ${xdr_file}"
    )

    set_source_files_properties(
        ${XDR_C} PROPERTIES COMPILE_OPTIONS -Wno-unused
    )

    include_directories(${CMAKE_CURRENT_BINARY_DIR})

    unit_test(${module} ${test_name} ${sources} ${XDR_C} ${XDR_H})

endmacro()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

add_subdirectory(core)
add_subdirectory(thread)
add_subdirectory(rpc2)
add_subdirectory(http)
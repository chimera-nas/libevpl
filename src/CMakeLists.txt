macro(unit_test module test_name)

    set(sources ${ARGN})

    add_executable(${module}_${test_name} ${sources})

    target_link_libraries(${module}_${test_name} ${module} pthread)

    # Add the test
    add_test(NAME ${module}_${test_name} COMMAND ${module}_${test_name})

    set_tests_properties(${module}_${test_name} PROPERTIES LABELS ${module})
endmacro()

macro(unit_test_bin module test_name binary_name)

    add_test(NAME ${module}_${test_name} COMMAND ${TEST_BIN}/${binary_name} ${ARGN})

    set_tests_properties(${module}_${test_name} PROPERTIES LABELS ${module})
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

    add_dependencies(${module}_${test_name} xdrzcc)

endmacro()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(tests)
add_subdirectory(core)
add_subdirectory(socket)
add_subdirectory(thread)

if (HAVE_RDMACM)
    add_subdirectory(rdmacm)
endif()

if (HAVE_XLIO)
    add_subdirectory(xlio)
endif()


#add_subdirectory(rpc2)

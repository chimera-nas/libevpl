macro(unit_test module source_file)
    # Get the file name without extension
    get_filename_component(test_name ${source_file} NAME_WE)

    # Define the executable
    add_executable(${module}_${test_name} ${source_file})

    # Link libraries (add any required libraries here)
    target_link_libraries(${module}_${test_name} evpl_core pthread)

    # Add the test
    add_test(NAME ${module}_${test_name} COMMAND ${module}_${test_name})
endmacro()


include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(core)
add_subdirectory(rpc2)

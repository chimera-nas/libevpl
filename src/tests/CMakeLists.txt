set(TEST_BIN ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

macro(evpl_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} evpl)
    set_target_properties(${name} PROPERTIES
        TEST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c")
endmacro()

evpl_test(hello_world_msg)
evpl_test(hello_world_connected_msg) 
evpl_test(hello_world_stream)
evpl_test(ping_pong_msg)
evpl_test(ping_pong_connected_msg)
evpl_test(ping_pong_stream)
evpl_test(bulk_msg)
evpl_test(bulk_connected_msg)
evpl_test(bulk_stream)
evpl_test(rand_full_duplex_msg)
evpl_test(rand_full_duplex_stream)


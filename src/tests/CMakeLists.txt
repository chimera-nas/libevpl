add_executable(hello_world_msg hello_world_msg.c)
target_link_libraries(hello_world_msg evpl)

add_executable(hello_world_connected_msg hello_world_connected_msg.c)
target_link_libraries(hello_world_connected_msg evpl)

add_executable(hello_world_stream hello_world_stream.c)
target_link_libraries(hello_world_stream evpl)

add_executable(ping_pong_msg ping_pong_msg.c)
target_link_libraries(ping_pong_msg evpl)

add_executable(ping_pong_connected_msg ping_pong_connected_msg.c)
target_link_libraries(ping_pong_connected_msg evpl)

add_executable(ping_pong_stream ping_pong_stream.c)
target_link_libraries(ping_pong_stream evpl)

add_executable(bulk_msg bulk_msg.c)
target_link_libraries(bulk_msg evpl)

add_executable(bulk_connected_msg bulk_connected_msg.c)
target_link_libraries(bulk_connected_msg evpl)

add_executable(bulk_stream bulk_stream.c)
target_link_libraries(bulk_stream evpl)

add_executable(rand_full_duplex_msg rand_full_duplex_msg.c)
target_link_libraries(rand_full_duplex_msg evpl)

add_executable(rand_full_duplex_stream rand_full_duplex_stream.c)
target_link_libraries(rand_full_duplex_stream evpl)

set(TEST_BIN ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

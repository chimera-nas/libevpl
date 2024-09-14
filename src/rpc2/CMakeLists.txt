add_library(evpl_rpc2 SHARED 
    rpc2_server.c
    rpc2_client.c)

target_link_libraries(evpl_rpc2 evpl_core)

add_subdirectory(tests)

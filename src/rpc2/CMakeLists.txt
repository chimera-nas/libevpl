add_library(eventpoll_rpc2 SHARED 
    rpc2_server.c
    rpc2_client.c)

target_link_libraries(eventpoll_rpc2 eventpoll_core)

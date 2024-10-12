if (DEFINED ENV{EVPL_RDMACM_IP})
    SET(ADDR $ENV{EVPL_RDMACM_IP})
else()
    set(ADDR 127.0.0.1)
endif()

unit_test_bin(evpl hello_world_msg_xlio_udp hello_world_msg -r DATAGRAM_XLIO_UDP -a ${ADDR})
unit_test_bin(evpl hello_world_stream_xlio_tcp hello_world_stream -r STREAM_XLIO_TCP -a ${ADDR})

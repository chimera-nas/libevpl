# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

# Generate test certificates
set(TLS_TEST_CERT_DIR ${CMAKE_CURRENT_BINARY_DIR})
add_custom_command(
    OUTPUT ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/key.pem ${TLS_TEST_CERT_DIR}/ca.pem
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_test_certs.sh ${TLS_TEST_CERT_DIR}
    COMMENT "Generating test TLS certificates"
)

add_custom_target(tls_test_certs ALL
    DEPENDS ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/key.pem ${TLS_TEST_CERT_DIR}/ca.pem
)

# No wrapper script needed since tests set paths directly

# TLS tests using the same test binaries as socket tests
# We need to ensure certificates are generated before running tests
add_dependencies(hello_world_stream tls_test_certs)
add_dependencies(hello_world_connected_msg tls_test_certs)
add_dependencies(ping_pong_stream tls_test_certs)
add_dependencies(ping_pong_connected_msg tls_test_certs)
add_dependencies(bulk_connected_msg tls_test_certs)
add_dependencies(bulk_stream tls_test_certs)
add_dependencies(rand_full_duplex_stream tls_test_certs)

# TLS tests using the same test binaries as socket tests
unit_test_bin(tls hello_world_stream_tls hello_world_stream -r STREAM_SOCKET_TLS)
unit_test_bin(tls hello_world_connected_msg_tls hello_world_connected_msg -r STREAM_SOCKET_TLS)

unit_test_bin(tls ping_pong_stream_tls ping_pong_stream -r STREAM_SOCKET_TLS)
unit_test_bin(tls ping_pong_msg_tls ping_pong_connected_msg -r STREAM_SOCKET_TLS)

unit_test_bin(tls bulk_msg_tls bulk_connected_msg -r STREAM_SOCKET_TLS)
unit_test_bin(tls bulk_stream_tls bulk_stream -r STREAM_SOCKET_TLS)

unit_test_bin(tls rand_full_duplex_stream_tls rand_full_duplex_stream -r STREAM_SOCKET_TLS)
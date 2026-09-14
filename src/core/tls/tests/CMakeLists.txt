# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

find_program(EVPL_OPENSSL_EXECUTABLE openssl
    HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_HOST_TRIPLET}/tools/openssl" REQUIRED)
# Generate test certificates
set(TLS_TEST_CERT_DIR ${CMAKE_CURRENT_BINARY_DIR})
add_custom_command(
    OUTPUT ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/key.pem ${TLS_TEST_CERT_DIR}/ca.pem
    COMMAND ${EVPL_OPENSSL_EXECUTABLE} genrsa -out ${TLS_TEST_CERT_DIR}/key.pem 2048
    COMMAND ${EVPL_OPENSSL_EXECUTABLE} req -new -x509 -key ${TLS_TEST_CERT_DIR}/key.pem
            -out ${TLS_TEST_CERT_DIR}/cert.pem -days 365 -subj "/CN=localhost"
    COMMAND ${CMAKE_COMMAND} -E copy ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/ca.pem
    VERBATIM
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
unit_test_bin_all_mechs(tls hello_world_stream_tls hello_world_stream -r STREAM_SOCKET_TLS)
unit_test_bin_all_mechs(tls hello_world_connected_msg_tls hello_world_connected_msg -r STREAM_SOCKET_TLS)

unit_test_bin_all_mechs(tls ping_pong_stream_tls ping_pong_stream -r STREAM_SOCKET_TLS)
unit_test_bin_all_mechs(tls ping_pong_msg_tls ping_pong_connected_msg -r STREAM_SOCKET_TLS)

unit_test_bin_all_mechs(tls bulk_msg_tls bulk_connected_msg -r STREAM_SOCKET_TLS)
unit_test_bin_all_mechs(tls bulk_stream_tls bulk_stream -r STREAM_SOCKET_TLS)

unit_test_bin_all_mechs(tls rand_full_duplex_stream_tls rand_full_duplex_stream -r STREAM_SOCKET_TLS)
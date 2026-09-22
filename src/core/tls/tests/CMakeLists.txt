# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

set(TLS_TEST_CERT_DIR ${CMAKE_CURRENT_BINARY_DIR})
if(WIN32)
    find_program(EVPL_PWSH_EXECUTABLE pwsh REQUIRED)
    add_custom_command(
        OUTPUT ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/key.pem ${TLS_TEST_CERT_DIR}/ca.pem
        COMMAND ${EVPL_PWSH_EXECUTABLE} -NoProfile -File ${CMAKE_CURRENT_SOURCE_DIR}/generate_test_certs.ps1
                -Directory ${TLS_TEST_CERT_DIR}
        BYPRODUCTS ${TLS_TEST_CERT_DIR}/rsa-key.pem ${TLS_TEST_CERT_DIR}/expired.pem
                   ${TLS_TEST_CERT_DIR}/ec-cert.pem ${TLS_TEST_CERT_DIR}/ec-key.pem
        DEPENDS generate_test_certs.ps1
        VERBATIM)
else()
find_program(EVPL_OPENSSL_EXECUTABLE openssl
    HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_HOST_TRIPLET}/tools/openssl" REQUIRED)
# Generate test certificates
add_custom_command(
    OUTPUT ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/key.pem ${TLS_TEST_CERT_DIR}/ca.pem
    COMMAND ${EVPL_OPENSSL_EXECUTABLE} genrsa -out ${TLS_TEST_CERT_DIR}/key.pem 2048
    COMMAND ${EVPL_OPENSSL_EXECUTABLE} req -new -x509 -key ${TLS_TEST_CERT_DIR}/key.pem
            -out ${TLS_TEST_CERT_DIR}/cert.pem -days 365 -subj "/CN=localhost"
    COMMAND ${CMAKE_COMMAND} -E copy ${TLS_TEST_CERT_DIR}/cert.pem ${TLS_TEST_CERT_DIR}/ca.pem
    VERBATIM
    COMMENT "Generating test TLS certificates"
)

endif()

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

if(WIN32)
    add_executable(tls_identity identity.c)
    target_link_libraries(tls_identity PRIVATE evpl)
    add_dependencies(tls_identity tls_test_certs)
    foreach(case rsa_pkcs8 rsa_pkcs1 ec_pkcs8 untrusted expired)
        set(cert cert.pem)
        set(key key.pem)
        set(ca ca.pem)
        set(success 1)
        if(case STREQUAL "rsa_pkcs1")
            set(key rsa-key.pem)
        elseif(case STREQUAL "ec_pkcs8")
            set(cert ec-cert.pem)
            set(key ec-key.pem)
            set(ca ec-cert.pem)
        elseif(case STREQUAL "untrusted")
            set(ca ec-cert.pem)
            set(success 0)
        elseif(case STREQUAL "expired")
            set(cert expired.pem)
            set(ca expired.pem)
            set(success 0)
        endif()
        add_test(NAME libevpl/tls/identity_${case}
                 COMMAND tls_identity ${TLS_TEST_CERT_DIR}/${cert} ${TLS_TEST_CERT_DIR}/${key}
                                      ${TLS_TEST_CERT_DIR}/${ca} ${success})
        set_tests_properties(libevpl/tls/identity_${case} PROPERTIES RESOURCE_LOCK evpl_net TIMEOUT 30)
    endforeach()
endif()

if(WIN32)
    foreach(protocol Tls12 Tls13)
        add_test(NAME libevpl/tls/interop_${protocol}
                 COMMAND ${EVPL_PWSH_EXECUTABLE} -NoProfile -File ${CMAKE_CURRENT_SOURCE_DIR}/interop.ps1
                         -Server $<TARGET_FILE:tls_identity> -Directory ${TLS_TEST_CERT_DIR} -Protocol ${protocol})
        set_tests_properties(libevpl/tls/interop_${protocol} PROPERTIES RESOURCE_LOCK evpl_net TIMEOUT 45)
    endforeach()
endif()

if(WIN32)
    add_executable(tls_key_cleanup key_cleanup.c)
    target_link_libraries(tls_key_cleanup PRIVATE ncrypt)
endif()

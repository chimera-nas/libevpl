# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(http basic http_basic.c)
unit_test(http chunked http_chunked.c)

target_link_libraries(http_basic evpl_http curl)
target_link_libraries(http_chunked evpl_http curl)

# evpl HTTP/1.1 client <-> evpl server (no nghttp2 required)
unit_test(http client http1_client.c)
target_link_libraries(http_client evpl_http)

if (HAVE_NGHTTP2)
    # evpl HTTP/2 client <-> evpl server (h2c prior-knowledge, and h2 over TLS)
    unit_test(http h2_client http2_client.c)
    target_link_libraries(http_h2_client evpl_http)

    unit_test(http h2_client_tls http2_client_tls.c)
    target_link_libraries(http_h2_client_tls evpl_http)

    # libevpl HTTP/2 server driven by libcurl (reference client)
    unit_test(http h2_basic http2_basic.c)
    target_link_libraries(http_h2_basic evpl_http curl)

    unit_test(http h2_tls http2_tls.c)
    target_link_libraries(http_h2_tls evpl_http curl)
endif()

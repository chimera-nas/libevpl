
add_library(evpl_http SHARED http.c)

target_link_libraries(evpl_http evpl)

install(TARGETS evpl_http DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
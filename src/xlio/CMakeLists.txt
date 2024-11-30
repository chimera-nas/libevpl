
add_library(evpl_xlio SHARED xlio.c tcp.c)

install(TARGETS evpl_xlio DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

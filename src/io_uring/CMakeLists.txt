add_library(evpl_io_uring SHARED io_uring.c)

target_link_libraries(evpl_io_uring uring)

install(TARGETS evpl_io_uring DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()


add_library(evpl_thread SHARED thread.c)

install(TARGETS evpl_thread DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

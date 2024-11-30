
add_library(evpl_rdmacm SHARED rdmacm.c)

target_link_libraries(evpl_rdmacm rdmacm ibverbs)

install(TARGETS evpl_rdmacm DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

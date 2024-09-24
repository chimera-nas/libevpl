
add_library(evpl_rdmacm SHARED rdmacm.c)

target_link_libraries(evpl_rdmacm rdmacm)

add_subdirectory(tests)

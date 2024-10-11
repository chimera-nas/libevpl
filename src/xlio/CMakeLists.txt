
add_library(evpl_xlio SHARED xlio.c udp.c epoll.c)

add_subdirectory(tests)

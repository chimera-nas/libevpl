
add_library(evpl_xlio SHARED xlio.c udp.c tcp.c epoll.c)

add_subdirectory(tests)

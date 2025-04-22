add_subdirectory(prometheus-c)
add_subdirectory(xdrzcc)

set(XDRZCC ${XDRZCC} PARENT_SCOPE)
message(STATUS "XDRZCC: ${XDRZCC}")

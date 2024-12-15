add_definitions(-DXDR_CUSTOM_IOVEC=${CMAKE_CURRENT_SOURCE_DIR}/xdr_iovec.h)
add_definitions(-DXDR_CUSTOM_DUMP=1)

set(RPC2_XDR_C ${CMAKE_CURRENT_BINARY_DIR}/rpc2_xdr.c)
set(RPC2_XDR_H ${CMAKE_CURRENT_BINARY_DIR}/rpc2_xdr.h)
set(RPC2_XDR_X ${CMAKE_CURRENT_SOURCE_DIR}/rpc2.x)

set(RPCRDMA1_XDR_C ${CMAKE_CURRENT_BINARY_DIR}/rpcrdma1_xdr.c)
set(RPCRDMA1_XDR_H ${CMAKE_CURRENT_BINARY_DIR}/rpcrdma1_xdr.h)
set(RPCRDMA1_XDR_X ${CMAKE_CURRENT_SOURCE_DIR}/rpcrdma1.x)

add_custom_command(
    OUTPUT ${RPC2_XDR_C} ${RPC2_XDR_H}
    COMMAND ${XDRZCC} ${RPC2_XDR_X} ${RPC2_XDR_C} ${RPC2_XDR_H}
    DEPENDS ${RPC2_XDR_X} ${XDRZCC}
    COMMENT "Compiling ${RPC2_XDR_X}"
)

add_custom_command(
    OUTPUT ${RPCRDMA1_XDR_C} ${RPCRDMA1_XDR_H}
    COMMAND ${XDRZCC} ${RPCRDMA1_XDR_X} ${RPCRDMA1_XDR_C} ${RPCRDMA1_XDR_H}
    DEPENDS ${RPCRDMA1_XDR_X} ${XDRZCC}
    COMMENT "Compiling ${RPCRDMA1_XDR_X}"
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set_source_files_properties(
    ${RPC2_XDR_C} PROPERTIES COMPILE_OPTIONS -Wno-unused
)

set_source_files_properties(
    ${RPCRDMA1_XDR_C} PROPERTIES COMPILE_OPTIONS -Wno-unused
)

add_library(evpl_rpc2 SHARED rpc2.c ${RPC2_XDR_C} ${RPC2_XDR_H} ${RPCRDMA1_XDR_C} ${RPCRDMA1_XDR_H} custom_dump.c)

add_dependencies(evpl_rpc2 xdrzcc)

target_link_libraries(evpl_rpc2 evpl)

install(TARGETS evpl_rpc2 DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

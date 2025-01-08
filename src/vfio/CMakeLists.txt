add_library(evpl_vfio SHARED vfio.c)

install(TARGETS evpl_vfio DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
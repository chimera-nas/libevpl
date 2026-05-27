# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

#unit_test(vfio basic basic.c)

# Standalone VFIO block microbench (not a ctest -- needs a real VFIO NVMe).
# Run directly: vfio_bench <pci-bdf> [seconds-per-level] [block-bytes]
add_executable(vfio_bench bench.c)
target_link_libraries(vfio_bench evpl pthread)
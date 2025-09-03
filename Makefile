# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

CMAKE_ARGS := -G Ninja -DCMAKE_C_COMPILER=gcc
CMAKE_ARGS_RELEASE := -DCMAKE_BUILD_TYPE=Release
CMAKE_ARGS_DEBUG := -DCMAKE_BUILD_TYPE=Debug
CTEST_ARGS := --output-on-failure --timeout 10

# Use LIBEVPL_BUILD_DIR if set (for devcontainer), otherwise use build subdirectory
BUILD_DIR ?= $(if $(LIBEVPL_BUILD_DIR),$(LIBEVPL_BUILD_DIR),build)

SOURCE_DIR := $(shell pwd)

default: release

.PHONY: build_release
build_release: 
	@mkdir -p ${BUILD_DIR}/Release
	@cmake ${CMAKE_ARGS} ${CMAKE_ARGS_RELEASE} -S . -B ${BUILD_DIR}/Release
	@ninja -C ${BUILD_DIR}/Release

.PHONY: build_debug
build_debug:
	@mkdir -p ${BUILD_DIR}/Debug
	@cmake ${CMAKE_ARGS} ${CMAKE_ARGS_DEBUG} -S . -B ${BUILD_DIR}/Debug
	@ninja -C ${BUILD_DIR}/Debug

.PHONY: test_debug
test_debug: build_debug
	cd ${BUILD_DIR}/Debug && ctest ${CTEST_ARGS}

.PHONY: test_release
test_release: build_release
	cd ${BUILD_DIR}/Release && ctest ${CTEST_ARGS}

.PHONY: debug
debug: build_debug test_debug

.PHONY: release
release: build_release test_release

clean:
	@rm -rf ${BUILD_DIR}


.PHONY: syntax-check
syntax-check:
	@find src/ -type f \( -name "*.c" -o -name "*.h" \) -print0 | \
                xargs -0 -I {} sh -c 'uncrustify -c etc/uncrustify.cfg --check {} >/dev/null 2>&1 || (echo "Formatting issue in: {}" && exit 1)' || exit 1


.PHONY: syntax
syntax:
	@find src/ -type f \( -name "*.c" -o -name "*.h" \) -print0 | \
                xargs -0 -I {} sh -c 'uncrustify -c etc/uncrustify.cfg --replace --no-backup {}' >/dev/null 2>&1
		

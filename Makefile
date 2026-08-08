# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

CMAKE_ARGS := -G Ninja
CMAKE_ARGS_RELEASE := -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc
CMAKE_ARGS_DEBUG := -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc
# Coverage uses clang's source-based coverage, so force the clang toolchain
# (the compiler pin moved out of CMAKE_ARGS so this build type can differ).
CMAKE_ARGS_COVERAGE := -DCMAKE_BUILD_TYPE=Coverage -DCMAKE_C_COMPILER=clang
CTEST_ARGS := --output-on-failure --timeout 10
# The Coverage build is -O0 with instrumentation on every TU, so tests run
# appreciably slower than the Release/Debug builds the 10s timeout was chosen
# for.  Give them room rather than collecting timeouts as coverage gaps.
CTEST_ARGS_COVERAGE := --output-on-failure --timeout 60

# Restrict the coverage run to a subset of the suite:
#
#   make coverage COVERAGE_TESTS=conformance
#
# The value is a ctest -R regex.  Empty (the default) runs everything.  Useful
# for asking what one test actually reaches -- the report then reflects only
# the filtered run, since the profile directory is cleared each time.
COVERAGE_TESTS ?=
CTEST_FILTER := $(if ${COVERAGE_TESTS},-R ${COVERAGE_TESTS},)

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

.PHONY: build_coverage
build_coverage:
	@mkdir -p ${BUILD_DIR}/Coverage
	@cmake ${CMAKE_ARGS} ${CMAKE_ARGS_COVERAGE} -S . -B ${BUILD_DIR}/Coverage
	@ninja -C ${BUILD_DIR}/Coverage

# Run the suite against the instrumented build, then merge the raw profiles and
# print a coverage report. Each test writes its own profile via the %m/%p
# patterns; the path is absolute so it survives the cwd changes and netns hops
# the tests make. The report runs even when tests fail, since partial coverage
# from a failing run is still worth reading.
COVERAGE_DIR := $(abspath ${BUILD_DIR}/Coverage)/coverage
.PHONY: test_coverage
test_coverage: build_coverage
	@rm -rf ${COVERAGE_DIR}
	@mkdir -p ${COVERAGE_DIR}/profraw
	-cd ${BUILD_DIR}/Coverage && \
		LLVM_PROFILE_FILE=${COVERAGE_DIR}/profraw/%m-%p.profraw ctest ${CTEST_ARGS_COVERAGE} ${CTEST_FILTER}
	@bash etc/coverage-report.sh ${BUILD_DIR}/Coverage

.PHONY: debug
debug: build_debug test_debug

.PHONY: release
release: build_release test_release

.PHONY: coverage
coverage: build_coverage test_coverage

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
		

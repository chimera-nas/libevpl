
default: test

.PHONY: build_release
build_release: 
	@mkdir -p build
	@cmake -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release -S . -B build
	@make -C build

.PHONY: build_debug
build_debug:
	@mkdir -p build
	@cmake -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -S . -B build
	@make -C build

.PHONY: test_debug
test_debug: build_debug
	cd build && ctest --output-on-failure 

.PHONY: test_release
test_release: build_release
	cd build && ctest --output-on-failure

test: test_debug

clean:
	@rm -rf build
		

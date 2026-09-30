BUILD_DIR ?= build
CMAKE_BUILD_TYPE ?= Release
CMAKE ?= cmake

.PHONY: all configure test run clean

all: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)

test: configure
	$(CMAKE) --build $(BUILD_DIR) --target test_packet --parallel
	ctest --test-dir $(BUILD_DIR) --output-on-failure

run: all
	$(BUILD_DIR)/pacp

clean:
	$(CMAKE) -E remove_directory $(BUILD_DIR)

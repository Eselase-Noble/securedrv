# =============================================================================
#  Cipherjet — convenience Makefile wrapping the CMake build.
#
#    make            build in Release mode
#    make test       build and run the unit tests
#    make install    install the binaries to the system (sudo)
#    make printer    build + register the "Cipherjet (Encrypted)" printer (sudo)
#    make uninstall  remove the printer + installed binaries (sudo)
#    make clean      remove the build directory
# =============================================================================
BUILD_DIR ?= build
BUILD_TYPE ?= Release

.PHONY: all build test install printer uninstall clean

all: build

build:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)
	cmake --build $(BUILD_DIR) -j

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

install: build
	sudo cmake --install $(BUILD_DIR)

printer: build
	sudo ./install/install-cups-printer.sh

uninstall:
	sudo ./install/uninstall-cups-printer.sh

clean:
	rm -rf $(BUILD_DIR)

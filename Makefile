# Makefile for LAN Router & SOCKS5 Proxy Manager

BINARY_NAME=lan_proxy
VERSION=1.0.0
BUILD_DIR=build

.PHONY: all clean build-local linux windows darwin router all-platforms

all: clean build-local

# Build for current machine
build-local:
	@echo "Building for current platform..."
	go build -o $(BINARY_NAME) main.go
	@echo "Build complete: ./$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BINARY_NAME) $(BUILD_DIR)

# Linux (AMD64)
linux:
	@echo "Building for Linux AMD64..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go

# Windows (AMD64)
windows:
	@echo "Building for Windows AMD64..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go

# macOS (Intel & Apple Silicon)
darwin:
	@echo "Building for macOS AMD64 & ARM64..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go

# Routers (OpenWrt / ARM / MIPS)
# Common router architectures:
# - armv7 / aarch64 (Hardlinx, newer Netgear/Xiaomi/Asus routers)
# - mips / mipsle (Traditional routers, MT7621, AR9341 etc.)
router:
	@echo "Building for Router architectures (OpenWrt/Embedded)..."
	mkdir -p $(BUILD_DIR)
	# ARM v7 (e.g. arm-based routers)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o $(BUILD_DIR)/$(BINARY_NAME)-router-armv7 main.go
	# ARM 64 (e.g. newer ARM64 routers)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-router-arm64 main.go
	# MIPSLE (Little Endian, e.g. MT7620/MT7621 based routers like Newifi D1, K2P)
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o $(BUILD_DIR)/$(BINARY_NAME)-router-mipsle main.go
	# MIPS (Big Endian)
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -o $(BUILD_DIR)/$(BINARY_NAME)-router-mips main.go

# Build for all supported platforms
all-platforms: clean linux windows darwin router
	@echo "All platforms built successfully! Check $(BUILD_DIR)/ directory."

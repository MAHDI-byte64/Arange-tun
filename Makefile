BIN      := arange-tun
BIN_PATH := /usr/local/bin/arange-tun
LDFLAGS  := -s -w

.PHONY: all build install uninstall clean tidy run vendor release-linux release version

all: build

tidy:
	go mod tidy

# Sync the raw VERSION file (used by the updater's mirror path) with the
# app.Version constant, so they can never drift.
version:
	@grep -oE 'Version = "[^"]+"' internal/app/app.go | grep -oE 'v[0-9.]+' > VERSION
	@echo "VERSION -> $$(cat VERSION)"

# cgo is on: the Packet tunnel's pcap engine links against libpcap. The build
# needs a C compiler and the libpcap development headers (libpcap-dev /
# libpcap-devel); the installer puts them on the machine.
build: tidy
	CGO_ENABLED=1 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

vendor:
	go mod tidy
	go mod vendor

# Cross-compile Linux binaries. Because of cgo/libpcap these are dynamically
# linked against libpcap and each target arch needs its own C cross-toolchain
# and libpcap headers (e.g. gcc-aarch64-linux-gnu + libpcap-dev:arm64 for arm64).
release-linux:
	mkdir -p dist
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/arange-tun-linux-amd64 .
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc go build -trimpath -ldflags "$(LDFLAGS)" -o dist/arange-tun-linux-arm64 .

# GitHub release assets: arange-tun_linux_<arch>.tar.gz, each containing a single
# `arange-tun` binary. These are what install.sh and the in-app updater download.
release: version release-linux
	mkdir -p release
	cp dist/arange-tun-linux-amd64 dist/arange-tun && tar -czf release/arange-tun_linux_amd64.tar.gz -C dist arange-tun && rm dist/arange-tun
	cp dist/arange-tun-linux-arm64 dist/arange-tun && tar -czf release/arange-tun_linux_arm64.tar.gz -C dist arange-tun && rm dist/arange-tun
	@# A checksum file published beside the assets is what lets the installer and
	@# the updater prove that a mirror handed them the real binary. Users on
	@# restricted networks fetch these through third-party proxies, so this is
	@# the only integrity check they get.
	cd release && (sha256sum arange-tun_linux_*.tar.gz > SHA256SUMS 2>/dev/null || shasum -a 256 arange-tun_linux_*.tar.gz > SHA256SUMS)
	@echo "Release assets ready in ./release"
	@cat release/SHA256SUMS

install: build
	install -m 0755 $(BIN) $(BIN_PATH)
	mkdir -p /etc/arange-tun
	@echo "Installed. Run: arange-tun"

uninstall:
	rm -f $(BIN_PATH)

run: build
	sudo ./$(BIN)

clean:
	rm -f $(BIN)

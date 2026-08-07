#!/usr/bin/env bash
#
# Arange-tun installer — one command on the VPS (as root):
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/mahdi-byte64/Arange-tun/main/install.sh)
#
# It builds Arange-tun from source: if run inside a source checkout it builds
# that; otherwise it downloads the current source from GitHub into
# /root/Arange-tun and builds it there. Go is installed automatically if the
# machine does not already have a new enough toolchain. No prebuilt releases are
# used — the binary is always compiled from the source you can read in this repo.
#
# When it finishes it opens the menu automatically (on an interactive terminal).
# Later, reopen it any time with:  sudo arange-tun
#
set -euo pipefail

RED='\033[0;31m'; WHITE='\033[1;37m'; GRAY='\033[0;90m'; NC='\033[0m'
info() { echo -e "${WHITE}[*]${NC} $*"; }
warn() { echo -e "${GRAY}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

REPO="mahdi-byte64/Arange-tun"
BRANCH="main"
BIN_PATH="/usr/local/bin/arange-tun"
INSTALL_DIR="/root/Arange-tun"
GO_VERSION="1.24.5"
GO_MIN_MINOR=24
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/tmp}")" 2>/dev/null && pwd || echo /tmp)"

if [[ $EUID -ne 0 ]]; then err "Please run as root (sudo)."; exit 1; fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

mkdir -p /etc/arange-tun "$INSTALL_DIR/backups"

# fetch <url> <out> — straight to GitHub, so TLS terminates there.
fetch() {
  curl -fsSL --connect-timeout 15 "$1" -o "$2"
}

# ---------------------------------------------------------------------------
# Go toolchain — installed automatically when the machine has none new enough.
# ---------------------------------------------------------------------------
download_go() {
  local file="go${GO_VERSION}.linux-${ARCH}.tar.gz" out="$1"
  for u in "https://go.dev/dl/${file}" \
           "https://golang.google.cn/dl/${file}" \
           "https://mirrors.aliyun.com/golang/${file}"; do
    info "Trying ${u}"
    curl -fsSL --connect-timeout 15 "$u" -o "$out" && return 0
    warn "source failed, trying next..."
  done
  return 1
}
go_new_enough() {
  local v; v="$("$1" version 2>/dev/null | grep -oE 'go1\.[0-9]+' | head -1)"; v="${v#go1.}"
  [[ -n "$v" ]] && (( v >= GO_MIN_MINOR ))
}
ensure_go() {
  command -v go >/dev/null 2>&1 && go_new_enough "$(command -v go)" && { info "Go: $(go version)"; return; }
  [[ -x /usr/local/go/bin/go ]] && go_new_enough /usr/local/go/bin/go && { export PATH="/usr/local/go/bin:$PATH"; info "Go: $(go version)"; return; }
  warn "Installing Go ${GO_VERSION}..."; download_go /tmp/go-at.tgz || { err "Could not obtain Go."; exit 1; }
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go-at.tgz; export PATH="/usr/local/go/bin:$PATH"; info "$(go version)"
}

# ---------------------------------------------------------------------------
# Build. build_from_source compiles whatever is in SCRIPT_DIR; fetch_source
# downloads the current source from GitHub first when there is no local checkout.
# ---------------------------------------------------------------------------
build_from_source() {
  cd "$SCRIPT_DIR"
  ensure_go; export PATH="/usr/local/go/bin:$PATH"
  # Direct module fetching first, Iran-friendly mirrors as fallback.
  export GOPROXY="https://proxy.golang.org,https://mirror-go.runflare.com,https://goproxy.cn,direct"
  export GOSUMDB=off GOTOOLCHAIN=local
  info "Building from source (proxy order: direct first, then mirrors)."
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN_PATH" .
  echo "$INSTALL_DIR" > /etc/arange-tun/install_path
}

fetch_source() {
  local url="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
  local tarball="$INSTALL_DIR/source.tar.gz"
  info "Downloading source from ${REPO}@${BRANCH}..."
  fetch "$url" "$tarball" || {
    err "Could not download the source from GitHub. This server may not be able"
    err "to reach github.com. Clone the repo on a machine that can and run"
    err "'sudo bash install.sh' inside the clone."
    exit 1
  }
  rm -rf "$INSTALL_DIR/src"; mkdir -p "$INSTALL_DIR/src"
  tar xzf "$tarball" -C "$INSTALL_DIR/src" --strip-components=1
  rm -f "$tarball"
  SCRIPT_DIR="$INSTALL_DIR/src"
}

if [[ -f "$SCRIPT_DIR/go.mod" && -f "$SCRIPT_DIR/main.go" ]]; then
  info "Building from the local source checkout."
  build_from_source
else
  fetch_source
  build_from_source
fi
info "Built and installed -> ${BIN_PATH}"

# Record the commit just built, so the panel's update check can tell a later
# push apart from "nothing changed". Best-effort — a miss only means the first
# check offers a rebuild it did not strictly need.
sha="$(curl -fsSL --connect-timeout 15 "https://api.github.com/repos/${REPO}/commits/${BRANCH}" 2>/dev/null \
  | grep -oE '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{7,40}"' | head -1 | grep -oE '[0-9a-f]{7,40}' | head -1)"
[ -n "$sha" ] && echo "$sha" > /etc/arange-tun/installed_commit || true

chmod +x "$BIN_PATH"
echo
echo -e "${WHITE}Done!${NC}"

# Open the menu straight away — people miss the "now run sudo arange-tun" step.
# Only when there is an interactive terminal to read from: a piped install
# (curl ... | bash) has no tty on stdin, so it just prints the instruction. The
# script already runs as root, so the binary is launched directly. `exec`
# replaces this shell so the menu owns the terminal cleanly.
if [ -t 0 ]; then
  echo -e "Starting the menu... ${GRAY}(next time, just run ${NC}${RED}sudo arange-tun${GRAY})${NC}"
  echo
  exec "$BIN_PATH"
else
  echo -e "Open the menu with:  ${RED}sudo arange-tun${NC}"
fi

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
GO_MIN_PATCH=4   # go.mod requires go >= 1.24.4
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/tmp}")" 2>/dev/null && pwd || echo /tmp)"

# Module and toolchain fetching, set once for every go invocation in this run.
#
# GOTOOLCHAIN=local pins the build to whatever go is on PATH and forbids Go from
# downloading a newer toolchain — that download goes to proxy.golang.org, which
# returns 403 from a sanctioned region and would abort the whole build. We
# install a toolchain that satisfies go.mod, so local is always enough.
#
# GOPROXY lists Iran-reachable mirrors first and is pipe-separated ("|") on
# purpose: with commas Go only advances to the next proxy on a 404/410, so a
# 403 (what proxy.golang.org returns from Iran) is a hard stop that never
# reaches the mirrors. "|" makes it fall through on ANY error.
#
# The checksum database is deliberately NOT switched off. It used to be, which
# meant every dependency arrived from a third-party mirror on trust alone. It
# does not need to be off: go.sum in this repo pins every module the build uses,
# and Go consults the checksum database only for a module that go.sum does not
# already cover — so a normal build never contacts it, and a module that
# somehow is not covered fails loudly instead of being taken from a mirror
# unverified. That is the behaviour we want on exactly the networks this runs on.
export GOTOOLCHAIN=local
export GOPROXY="https://goproxy.cn|https://mirror-go.runflare.com|https://proxy.golang.org|direct"

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
# Where a Go toolchain may come from. Iran-reachable mirrors first, because
# go.dev/dl often 404s or geoblocks from Iran.
GO_MIRRORS=(
  "https://mirrors.aliyun.com/golang"
  "https://mirrors.ustc.edu.cn/golang"
  "https://golang.google.cn/dl"
  "https://go.dev/dl"
)

# Where a checksum may come from. The mirrors above all publish a .sha256 beside
# each archive, and Google's download CDN is listed as well: it is a different
# host from go.dev, so it counts as an independent source even when go.dev
# itself served the archive.
GO_SUM_SOURCES=(
  "${GO_MIRRORS[@]}"
  "https://dl.google.com/go"
)

# Set by download_go to the base URL the archive actually came from, so the
# checksum can be required to come from somewhere else.
GO_SOURCE_BASE=""

download_go() {
  local file="go${GO_VERSION}.linux-${ARCH}.tar.gz" out="$1" base
  for base in "${GO_MIRRORS[@]}"; do
    info "Trying ${base}/${file}"
    if curl -fsSL --connect-timeout 15 "${base}/${file}" -o "$out"; then
      GO_SOURCE_BASE="$base"
      return 0
    fi
    warn "source failed, trying next..."
  done
  return 1
}

# go_independent_sha256 <file> — the SHA256 published for <file> by a host other
# than the one that served the archive, or nothing when no such host answers.
#
# The compiler that builds the binary this server runs as root is the last thing
# that should arrive on trust, and it used to: whichever mirror answered first
# handed over eighty megabytes of toolchain and nothing checked what was in it.
# TLS proves the bytes left that mirror unaltered. It says nothing about the
# mirror, and these are third-party mirrors picked for being reachable from a
# censored network, not for being trusted.
#
# The fix is not "check a hash" — a mirror serving a modified archive would
# happily serve a matching hash next to it. It is that the hash must come from
# somewhere the archive did not. One other host is enough for that: a hostile
# mirror cannot change what an independent one publishes.
#
# If several independent hosts answer they must all say the same thing.
# Disagreement means one of them is lying, and there is no way from here to tell
# which — so it stops rather than guess.
go_independent_sha256() {
  local file="$1" base sum seen=""
  for base in "${GO_SUM_SOURCES[@]}"; do
    [[ "$base" == "$GO_SOURCE_BASE" ]] && continue
    sum="$(curl -fsSL --connect-timeout 10 --max-time 30 "${base}/${file}.sha256" 2>/dev/null \
      | tr -d '[:space:]' | tr 'A-F' 'a-f')" || true
    [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || continue
    if [[ -z "$seen" ]]; then
      seen="$sum"
    elif [[ "$seen" != "$sum" ]]; then
      err "Sources disagree about the checksum of ${file}:"
      err "  ${seen}"
      err "  ${sum}"
      err "One of them is serving something it should not be. Stopping."
      # Status 2, not `exit`: this function is called inside a command
      # substitution, where an exit would end only the subshell and let the
      # caller carry on to print a second, wrong explanation.
      return 2
    fi
  done
  [[ -n "$seen" ]] && echo "$seen"
  return 0
}

# verify_go_tarball <path> — abort unless the archive hashes to what an
# independent source says it should. GO_SHA256 in the environment pins the value
# by hand instead, for an operator who has the official checksum or whose
# network reaches only the one mirror.
verify_go_tarball() {
  local out="$1" file="go${GO_VERSION}.linux-${ARCH}.tar.gz" want got rc=0
  if [[ -n "${GO_SHA256:-}" ]]; then
    want="$(echo "$GO_SHA256" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
  else
    info "Checking the toolchain against an independent checksum..."
    # The status has to be captured on the assignment itself; reading $? inside
    # an `if ! ...` would read the negation, not what the function returned.
    want="$(go_independent_sha256 "$file")" && rc=0 || rc=$?
    # 2 means the sources contradicted each other, and it has said so already.
    [[ $rc -eq 2 ]] && exit 1
    [[ $rc -eq 0 ]] || want=""
  fi
  if [[ ! "$want" =~ ^[0-9a-f]{64}$ ]]; then
    err "No independent checksum for ${file} could be fetched — every source"
    err "other than the one that served the archive was unreachable."
    err "Refusing to build with an unverified Go toolchain. Either:"
    err "  - install Go ${GO_VERSION} or newer yourself and re-run this script"
    err "    (an existing toolchain on PATH is used as-is), or"
    err "  - re-run with the official checksum from https://go.dev/dl/:"
    err "      GO_SHA256=<sha256> bash install.sh"
    exit 1
  fi
  got="$(sha256sum "$out" | awk '{print $1}')"
  if [[ "$got" != "$want" ]]; then
    err "Checksum mismatch for ${file}."
    err "  expected ${want}"
    err "  got      ${got}"
    err "The download was corrupted or the mirror served something else."
    exit 1
  fi
  info "Toolchain checksum verified."
}
# go_new_enough accepts a go only if it satisfies the go.mod minimum (1.24.4).
# Checking the minor alone is not enough: with GOTOOLCHAIN=local a go1.24.0..3
# cannot build a module that requires 1.24.4 and would fail with no fallback, so
# the patch level has to clear GO_MIN_PATCH too.
go_new_enough() {
  local v minor patch
  v="$("$1" version 2>/dev/null | grep -oE 'go1\.[0-9]+(\.[0-9]+)?' | head -1)"; v="${v#go1.}"
  [[ -z "$v" ]] && return 1
  minor="${v%%.*}"
  patch="${v#*.}"; [[ "$patch" == "$v" ]] && patch=0
  (( minor > GO_MIN_MINOR )) && return 0
  (( minor == GO_MIN_MINOR && patch >= GO_MIN_PATCH ))
}
ensure_go() {
  command -v go >/dev/null 2>&1 && go_new_enough "$(command -v go)" && { info "Go: $(go version)"; return; }
  [[ -x /usr/local/go/bin/go ]] && go_new_enough /usr/local/go/bin/go && { export PATH="/usr/local/go/bin:$PATH"; info "Go: $(go version)"; return; }
  warn "Installing Go ${GO_VERSION}..."; download_go /tmp/go-at.tgz || { err "Could not obtain Go."; exit 1; }
  verify_go_tarball /tmp/go-at.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go-at.tgz; export PATH="/usr/local/go/bin:$PATH"; info "$(go version)"
}

# ---------------------------------------------------------------------------
# Native build prerequisites. The Packet tunnel embeds a raw-packet (pcap)
# engine, so the binary is compiled with cgo and needs a C compiler and the
# libpcap development headers. Everything else is pure Go. Installed once, then
# reused by the panel's build-from-source updater.
# ---------------------------------------------------------------------------
ensure_build_deps() {
  if command -v gcc >/dev/null 2>&1 && have_pcap_headers; then
    info "Build deps: gcc + libpcap present."
    return
  fi
  warn "Installing build prerequisites (gcc, libpcap headers)..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y gcc libpcap-dev >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc libpcap-devel >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc libpcap-devel >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache gcc musl-dev libpcap-dev >/dev/null 2>&1 || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm gcc libpcap >/dev/null 2>&1 || true
  else
    warn "Unknown package manager — install gcc and libpcap-dev/libpcap-devel manually if the build fails."
  fi
  if ! command -v gcc >/dev/null 2>&1 || ! have_pcap_headers; then
    warn "gcc or libpcap headers still missing; the build may fail. Install them for your distro and re-run."
  fi
}
have_pcap_headers() {
  [[ -f /usr/include/pcap/pcap.h || -f /usr/include/pcap.h ]]
}

# ---------------------------------------------------------------------------
# Build. build_from_source compiles whatever is in SCRIPT_DIR; fetch_source
# downloads the current source from GitHub first when there is no local checkout.
# ---------------------------------------------------------------------------
build_from_source() {
  cd "$SCRIPT_DIR"
  ensure_go; export PATH="/usr/local/go/bin:$PATH"
  ensure_build_deps
  # GOPROXY / GOSUMDB / GOTOOLCHAIN are exported once near the top of the script.
  info "Building from source (Iran-reachable module mirrors first)."
  # cgo is on: the Packet tunnel's pcap engine links against libpcap.
  CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o "$BIN_PATH" .
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

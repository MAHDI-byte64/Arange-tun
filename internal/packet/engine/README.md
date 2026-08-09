# Vendored `paqet` engine

This directory is a vendored copy of the **paqet** raw-packet proxy engine by
hanselime — <https://github.com/hanselime/paqet> — used under the MIT License
(see `LICENSE` in this directory).

It powers the **Packet** tunnel. Arange-tun does not download a paqet binary; the
engine is compiled into `arange-tun` from this source, in keeping with the
project's "no external tunnel binaries" rule.

## Local changes

The upstream `internal/` tree was copied here verbatim, with only these edits:

- Import paths rewritten from `paqet/internal/...` to
  `github.com/mahdi-byte64/arange-tun/internal/packet/engine/...`.
- Added `conf/prepare.go`: an exported `Prepare(*Conf)` that applies the same
  defaults and validation `LoadFromFile` runs, so the Arange-tun adapter
  (in the parent `internal/packet` package) can build the config in Go from its
  own TOML instead of writing a YAML file.

The upstream `cmd/` (a cobra CLI) is not vendored; its `run` wiring is
reimplemented in the adapter.

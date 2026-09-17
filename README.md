Hello, World.

## Install

```sh
brew install writtendev/tap/stet
```

Homebrew is macOS-only for now: the Linux binary has no rpath into the
Linuxbrew prefix, so `depends_on "libfido2"` in the formula doesn't make it
loadable there. On Linux, use the tarballs from the
[releases page](https://github.com/writtendev/stet/releases) instead.

Linux tarballs are built on Ubuntu 24.04 and link against the system
`libfido2`; they require glibc >= 2.39 and libfido2 >= 1.14 (`apt install
libfido2-1` on 24.04+). Older distros (Ubuntu 22.04, Debian 12, etc.) ship
older libfido2/glibc and will fail to load the binary.

## Building

stet's hardware key support (`internal/fido`) is a cgo binding to
[libfido2](https://github.com/Yubico/libfido2). Install it before building:

```sh
brew install libfido2       # macOS
apt install libfido2-dev    # Debian/Ubuntu
```

`make` detects it automatically: the `libfido2` build tag turns on when
`pkg-config --exists libfido2` succeeds, and the resulting binary talks to
real hardware security keys over CTAP2. Without it, `stet` still builds and
runs — every command works except hardware enrollment/signing, which fails
with a clear "libfido2 not available" error.

Override the detection with `FIDO2=1` (fail loudly if libfido2 truly isn't
installed) or `FIDO2=0` (force the no-hardware stub) if you need a
specific build, e.g. `make build test lint FIDO2=1`.

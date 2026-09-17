Hello, World.

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

# keyring

[![CI](https://github.com/go-keyring/keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/go-keyring/keyring/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-keyring/keyring.svg)](https://pkg.go.dev/github.com/go-keyring/keyring)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-keyring/keyring)](https://goreportcard.com/report/github.com/go-keyring/keyring)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go (`CGO_ENABLED=0`) cross-platform secret store: one small API — `Set` /
`Get` / `Delete` / `Available` over a `(service, account)` pair — dispatched to
the host platform's native credential vault. **No cgo, no CLI `exec`.**

| GOOS | Backend | Library |
| --- | --- | --- |
| darwin | login Keychain | [`go-macos/keychain`](https://github.com/go-macos/keychain) (owned, purego) |
| windows | Credential Manager | [`danieljoos/wincred`](https://github.com/danieljoos/wincred) (`x/sys/windows`) |
| linux | Secret Service | [`go-freedesktop/secretservice`](https://github.com/go-freedesktop/secretservice) (godbus) |

## API

```go
import "github.com/go-keyring/keyring"

// Store (adds on first write, overwrites in place afterwards).
err := keyring.Set("my-app", "alice@example.com", []byte(secret))

// Read (keyring.ErrNotFound when absent).
secret, err := keyring.Get("my-app", "alice@example.com")

// Remove (deleting an absent secret is not an error).
err = keyring.Delete("my-app", "alice@example.com")

// Is a secret store usable on this host?
ok := keyring.Available()
```

### User-presence gate

A write may request that later reads be authorised by the person at the keyboard:

```go
err := keyring.Set("my-app", "alice@example.com", []byte(secret), keyring.WithUserPresence())
```

Its reach is platform-dependent:

| GOOS | `WithUserPresence` |
| --- | --- |
| darwin | the item is written with a `SecAccessControl` (`kSecAccessControlUserPresence` + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`): it never leaves the device and every read raises the Touch ID / passcode prompt |
| windows, linux | best-effort: the Credential Manager and Secret Service expose no per-item presence flag through their pure-Go clients, so the option is accepted and ignored — the secret is still stored with the store's at-rest protection (DPAPI; the collection's encryption). Add an interactive gate (e.g. Windows Hello) at the application layer if needed |

The option never changes whether the write succeeds; it only strengthens the
stored item's protection where the platform supports it.

Errors are typed and comparable with `errors.Is`:

| Error | Meaning |
| --- | --- |
| `ErrNotFound` | `Get` found no secret for the pair |
| `ErrUnavailable` | no usable store: unsupported platform, or a host with no reachable vault (e.g. headless Linux with no Secret Service daemon) |

## No silent plaintext fallback

When no vault is reachable, every entry point returns `ErrUnavailable` — keyring
never falls back to writing a plaintext secret somewhere. A caller that sees
`ErrUnavailable` knows the secret was neither stored nor read, and can decide
what to do (prompt, refuse, or select an explicit encrypted-file store of its
own).

## Why own the façade?

`zalando/go-keyring` and `99designs/keyring` make compliant Windows/Linux
choices, but their macOS backends break this project's rules —
`zalando/go-keyring` shells out to `/usr/bin/security`, and `99designs/keyring`
uses the cgo `keybase/go-keychain`. keyring reuses the pure-Go Windows/Linux
libraries and owns the façade so darwin can use the pure-Go, `CGO_ENABLED=0`
[`go-macos/keychain`](https://github.com/go-macos/keychain).

## Testing

The OS-independent dispatch is covered to **100%** on every lane through
injected backend seams. Each platform backend is proven against its real vault:
a macOS Keychain round trip on darwin, a live Secret Service round trip on Linux
(against `gnome-keyring-daemon`), and the Credential Manager backend on Windows.
`CGO_ENABLED=0` throughout, cross-built for darwin, windows and the six 64-bit
Linux targets.

```sh
CGO_ENABLED=0 go test ./...
```

## License

BSD-3-Clause. See [LICENSE](LICENSE).

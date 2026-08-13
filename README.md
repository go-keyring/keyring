# keyring — pure-Go cross-platform secret store

`github.com/go-keyring/keyring` is a pure-Go, **CGO=0** cross-platform secret
store: one small API — `Set` / `Get` / `Delete` (and `Available`) — dispatched
per-OS to the platform's native credential vault. **No cgo, no CLI `exec`.**

| GOOS | Backend |
|---|---|
| darwin | macOS Keychain via `github.com/go-macos/keychain` (owned, purego) |
| windows | Windows Credential Manager via `github.com/danieljoos/wincred` (pure-Go, x/sys/windows) |
| linux | Secret Service (`org.freedesktop.Secret.Service`) via `github.com/go-freedesktop/secretservice` (godbus) |

Why not `zalando/go-keyring` or `99designs/keyring`? Their macOS backends break
this project's rules (zalando shells out to `/usr/bin/security`; 99designs uses
cgo `keybase/go-keychain`). We reuse their compliant Windows/Linux choices but
own the façade so darwin can use the pure-Go `go-macos/keychain`.

Headless Linux with no running Secret Service daemon returns a clear error (no
silent plaintext); an optional encrypted-file backend can be selected explicitly.

## License
BSD-3-Clause — copyright the go-keyring authors.

// Package keyring is a pure-Go (CGO_ENABLED=0) cross-platform secret store. It
// exposes one small API — [Set], [Get], [Delete] and [Available] over a
// (service, account) pair — and dispatches to the host platform's native
// credential vault:
//
//	GOOS     Backend
//	darwin   macOS Keychain      github.com/go-macos/keychain          (purego)
//	windows  Credential Manager  github.com/danieljoos/wincred         (x/sys/windows)
//	linux    Secret Service      github.com/go-freedesktop/secretservice (godbus)
//
// Every backend is pure-Go and links with no cgo and no CLI exec. On a platform
// with no supported store — or a headless Linux box with no running Secret
// Service daemon — every entry point returns [ErrUnavailable]. keyring never
// falls back to writing a plaintext secret somewhere silently: a caller that
// sees ErrUnavailable knows the secret was neither stored nor read.
//
//	err          := keyring.Set(service, account, secret)
//	secret, err  := keyring.Get(service, account)   // keyring.ErrNotFound if absent
//	err          := keyring.Delete(service, account)
//	ok           := keyring.Available()
package keyring

import "errors"

// Sentinel errors. They are stable and may be compared with [errors.Is].
var (
	// ErrNotFound is returned by [Get] when no secret exists for the
	// (service, account) pair.
	ErrNotFound = errors.New("keyring: secret not found")
	// ErrUnavailable is returned when no secret store is usable: an
	// unsupported platform, or a host with no reachable credential vault
	// (for example headless Linux with no Secret Service daemon).
	ErrUnavailable = errors.New("keyring: no secret store available")
)

// Backend seams, assigned in an init() by the per-GOOS backend file. Keeping
// the platform code behind these vars lets the OS-independent surface reach
// full coverage on every lane — tests swap the seams for fakes.
var (
	backendSet       func(service, account string, secret []byte) error
	backendGet       func(service, account string) ([]byte, error)
	backendDelete    func(service, account string) error
	backendAvailable func() bool
)

// Set stores secret under (service, account), replacing any existing value.
// It returns [ErrUnavailable] when no secret store is usable on this host.
func Set(service, account string, secret []byte) error {
	return backendSet(service, account, secret)
}

// Get returns the secret stored under (service, account). It returns
// [ErrNotFound] when no such secret exists and [ErrUnavailable] when no store
// is usable.
func Get(service, account string) ([]byte, error) {
	return backendGet(service, account)
}

// Delete removes the secret stored under (service, account). Deleting an absent
// secret is not an error. It returns [ErrUnavailable] when no store is usable.
func Delete(service, account string) error {
	return backendDelete(service, account)
}

// Available reports whether a usable secret store is reachable on this host.
// It writes nothing and never blocks on an interactive prompt.
func Available() bool {
	return backendAvailable()
}

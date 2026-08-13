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
//
// A write may request an interactive user-presence gate with the
// [WithUserPresence] option:
//
//	err := keyring.Set(service, account, secret, keyring.WithUserPresence())
//
// On darwin this maps to a macOS Keychain SecAccessControl gated by Touch ID or
// the device passcode (see [WithUserPresence] for the best-effort behaviour on
// windows and linux).
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

// config is the resolved set of [Option] values for a [Set].
type config struct {
	// userPresence requests that the stored secret be protected behind an
	// interactive user-presence check on read.
	userPresence bool
}

// Option customises a [Set]. Options are applied left to right.
type Option func(*config)

// WithUserPresence requests that the secret be stored behind an interactive
// user-presence gate, so a later read must be authorised by the person at the
// keyboard.
//
// The gate is enforced by the host vault and its reach differs per platform:
//
//   - darwin: the item is written with a SecAccessControl carrying
//     kSecAccessControlUserPresence and the accessibility class
//     kSecAttrAccessibleWhenUnlockedThisDeviceOnly — it never leaves this
//     device, and every read raises the system Touch ID / passcode prompt.
//   - windows, linux: best-effort. The Credential Manager and the freedesktop
//     Secret Service expose no per-item presence flag through their pure-Go
//     clients, so the option is accepted and ignored — the secret is still
//     stored with the store's own at-rest protection (DPAPI under the
//     Credential Manager; the collection's encryption under the Secret
//     Service). An application that needs an interactive gate on these
//     platforms adds it at its own layer (for example a Windows Hello consent
//     prompt) around the read.
//
// The option never changes whether the write succeeds; it only strengthens the
// protection of the stored item where the platform supports it.
func WithUserPresence() Option {
	return func(c *config) { c.userPresence = true }
}

// Backend seams, assigned in an init() by the per-GOOS backend file. Keeping
// the platform code behind these vars lets the OS-independent surface reach
// full coverage on every lane — tests swap the seams for fakes.
var (
	backendSet       func(service, account string, secret []byte, cfg config) error
	backendGet       func(service, account string) ([]byte, error)
	backendDelete    func(service, account string) error
	backendAvailable func() bool
)

// Set stores secret under (service, account), replacing any existing value.
// It returns [ErrUnavailable] when no secret store is usable on this host.
// Pass [WithUserPresence] to gate later reads behind an interactive
// user-presence check where the platform supports it.
func Set(service, account string, secret []byte, opts ...Option) error {
	var c config
	for _, o := range opts {
		o(&c)
	}
	return backendSet(service, account, secret, c)
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

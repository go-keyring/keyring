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
//   - windows, linux: the Credential Manager and the freedesktop Secret Service
//     expose no per-item presence flag through their pure-Go clients, so the
//     write stores the secret with the store's own at-rest protection (DPAPI
//     under the Credential Manager; the collection's encryption under the Secret
//     Service) and the interactive gate is enforced on the READ instead: a
//     [Get] passed [WithUserPresence] runs the backend's [presenceVerify] (a
//     Windows Hello / desktop-agent prompt) before returning the secret. Until a
//     backend installs a real verifier the check defaults to a no-op, so the
//     option is a harmless pass-through there.
//
// The option never changes whether the write succeeds; it only strengthens the
// protection of the stored item, at write time on darwin and at read time
// elsewhere.
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

// presenceVerify raises the platform's interactive user-presence check and
// returns nil only when the person at the keyboard authorises it (an error, e.g.
// a cancelled prompt, denies the read). It is consulted by [Get] when the caller
// passes [WithUserPresence] on a platform whose vault does not enforce presence
// itself. The default is a no-op: on darwin the macOS Keychain raises Touch ID
// from the item's own SecAccessControl during the read, so no façade-level check
// is needed; the windows and linux backends replace this in their init() with a
// Windows Hello / desktop-agent prompt.
var presenceVerify = func() error { return nil }

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
//
// Pass [WithUserPresence] to require an interactive user-presence check before
// the secret is returned — the read half of a secret written with the same
// option. On darwin the check is the macOS Keychain's own Touch ID prompt,
// raised from the item's SecAccessControl during retrieval; on windows and linux
// it is a façade-level prompt (Windows Hello / the desktop authentication agent).
// A denied or cancelled check fails the read, and the secret is not retrieved.
// Without the option Get never prompts.
func Get(service, account string, opts ...Option) ([]byte, error) {
	var c config
	for _, o := range opts {
		o(&c)
	}
	if c.userPresence {
		if err := presenceVerify(); err != nil {
			return nil, err
		}
	}
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

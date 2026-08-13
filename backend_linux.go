//go:build linux

package keyring

import (
	"errors"

	"github.com/go-freedesktop/secretservice"
)

// mapErr translates the secretservice sentinels to keyring's. A headless box
// with no running Secret Service daemon surfaces as [ErrUnavailable] — never a
// silent plaintext fallback.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, secretservice.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, secretservice.ErrUnavailable):
		return ErrUnavailable
	default:
		return err
	}
}

// On Linux the store is the freedesktop Secret Service (GNOME Keyring, KWallet,
// …), reached through the pure-Go (godbus) github.com/go-freedesktop/secretservice
// client.
func init() {
	// cfg is accepted but not acted on: the freedesktop Secret Service exposes
	// no per-item user-presence flag through this client, so WithUserPresence
	// is a best-effort no-op here (see its doc). The secret is still stored
	// under the collection's own encryption.
	backendSet = func(service, account string, secret []byte, _ config) error {
		return mapErr(secretservice.Set(service, account, secret))
	}
	backendGet = func(service, account string) ([]byte, error) {
		b, err := secretservice.Get(service, account)
		if err != nil {
			return nil, mapErr(err)
		}
		return b, nil
	}
	backendDelete = func(service, account string) error {
		return mapErr(secretservice.Delete(service, account))
	}
	backendAvailable = secretservice.Available
}

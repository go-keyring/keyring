//go:build darwin

package keyring

import (
	"errors"

	"github.com/go-macos/keychain"
)

// On macOS the store is the login Keychain, reached through the pure-Go
// (purego) github.com/go-macos/keychain binding. Its typed errors are
// translated to keyring's sentinels.
func init() {
	backendSet = func(service, account string, secret []byte) error {
		return keychain.Set(service, account, secret)
	}
	backendGet = func(service, account string) ([]byte, error) {
		b, err := keychain.Get(service, account)
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	backendDelete = func(service, account string) error {
		return keychain.Delete(service, account)
	}
	backendAvailable = func() bool {
		// Probe without writing: a lookup of an unlikely key returns
		// ErrNotFound when the Keychain is reachable, or ErrUnsupported if the
		// Security framework could not be loaded.
		_, err := keychain.Get("github.com/go-keyring/keyring", "availability-probe")
		return err == nil || errors.Is(err, keychain.ErrNotFound)
	}
}

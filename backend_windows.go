//go:build windows

package keyring

import (
	"errors"

	"github.com/danieljoos/wincred"
)

// target folds (service, account) into the single TargetName that the Windows
// Credential Manager keys a generic credential by.
func target(service, account string) string { return service + "/" + account }

// On Windows the store is the Credential Manager, reached through the pure-Go
// (x/sys/windows) github.com/danieljoos/wincred binding.
func init() {
	// cfg is accepted but not acted on: the Credential Manager exposes no
	// per-item user-presence flag through wincred, so WithUserPresence is a
	// best-effort no-op here (see its doc). The credential is still stored with
	// the account's DPAPI at-rest protection.
	backendSet = func(service, account string, secret []byte, _ config) error {
		cred := wincred.NewGenericCredential(target(service, account))
		cred.UserName = account
		cred.CredentialBlob = secret
		return cred.Write()
	}
	backendGet = func(service, account string) ([]byte, error) {
		cred, err := wincred.GetGenericCredential(target(service, account))
		if errors.Is(err, wincred.ErrElementNotFound) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return cred.CredentialBlob, nil
	}
	backendDelete = func(service, account string) error {
		cred, err := wincred.GetGenericCredential(target(service, account))
		if errors.Is(err, wincred.ErrElementNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return cred.Delete()
	}
	backendAvailable = func() bool {
		// Probe without writing: reading an unlikely target returns
		// ErrElementNotFound when the Credential Manager is reachable.
		_, err := wincred.GetGenericCredential("github.com/go-keyring/keyring/availability-probe")
		return err == nil || errors.Is(err, wincred.ErrElementNotFound)
	}
}

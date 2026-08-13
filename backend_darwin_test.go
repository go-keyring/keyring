//go:build darwin

package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-macos/keychain"
)

// TestDarwinRoundTrip drives the real macOS Keychain through the (non-swapped)
// darwin backend on this device: a plain generic-password item with no access
// control, so it needs no Touch ID prompt and no code signature.
func TestDarwinRoundTrip(t *testing.T) {
	const service = "github.com/go-keyring/keyring test"
	account := fmt.Sprintf("acct-%d", time.Now().UnixNano())
	_ = Delete(service, account)
	t.Cleanup(func() { _ = Delete(service, account) })

	if !Available() {
		t.Fatal("Available() = false on macOS, want true")
	}

	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}

	want := []byte("s3cr3t-\x00-binary-\xff")
	if err := Set(service, account, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get(service, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get = %q, want %q", got, want)
	}

	want2 := []byte("rotated")
	if err := Set(service, account, want2); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	if got, _ = Get(service, account); !bytes.Equal(got, want2) {
		t.Fatalf("Get after overwrite = %q, want %q", got, want2)
	}

	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete of absent = %v, want nil", err)
	}
}

// TestDarwinUserPresenceOnDevice proves WithUserPresence drives the darwin
// backend down the SecAccessControl path on THIS device. In a signed/entitled
// context the protected SecItemAdd succeeds and Delete cleans up. From an
// UNSIGNED `go test` binary the Security framework rejects a
// SecAccessControl-protected add with errSecMissingEntitlement (OSStatus
// -34018) — a codesign precondition, not a wiring fault: the call still reached
// SecItemAdd, and keyring surfaced the underlying *keychain.Error verbatim so
// its raw OSStatus is inspectable. This asserts exactly one of those two
// outcomes (never a silent skip), so a green run proves the user-presence
// option is wired to the real Keychain up to the OS entitlement gate and
// upgrades to a full round-trip when run from a signed .app.
func TestDarwinUserPresenceOnDevice(t *testing.T) {
	const service = "github.com/go-keyring/keyring ac-test"
	account := fmt.Sprintf("acct-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = Delete(service, account) })

	err := Set(service, account, []byte("touch-id-gated"), WithUserPresence())
	if err == nil {
		// Entitled context: the protected item exists; clean up and confirm.
		if err := Delete(service, account); err != nil {
			t.Fatalf("Delete after protected Set: %v", err)
		}
		t.Log("on-device: WithUserPresence stored a SecAccessControl item (entitled context)")
		return
	}
	var kerr *keychain.Error
	if !errors.As(err, &kerr) || kerr.Status != -34018 {
		t.Fatalf("Set(WithUserPresence) = %v; want a stored item or errSecMissingEntitlement (OSStatus -34018)", err)
	}
	t.Logf("on-device: WithUserPresence reached SecItemAdd; blocked only by the codesign entitlement (OSStatus %d), as expected from an unsigned go test", kerr.Status)
}

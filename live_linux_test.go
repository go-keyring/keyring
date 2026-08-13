//go:build linux

package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLinuxLiveRoundTrip drives the real Secret Service backend through the
// façade against a running gnome-keyring-daemon. It is gated on the outer env
// var KEYRING_LIVE=1 only: once opted in, an unreachable daemon is a FAILURE,
// never a skip (a skip in a lane whose job is to prove the backend would look
// like proof and be none).
func TestLinuxLiveRoundTrip(t *testing.T) {
	if os.Getenv("KEYRING_LIVE") != "1" {
		t.Skip("set KEYRING_LIVE=1 to run the live Secret Service round-trip")
	}
	if !Available() {
		t.Fatal("Available() = false with KEYRING_LIVE=1: no reachable Secret Service daemon")
	}

	const service = "github.com/go-keyring/keyring live-test"
	account := fmt.Sprintf("acct-%d", time.Now().UnixNano())
	_ = Delete(service, account)
	t.Cleanup(func() { _ = Delete(service, account) })

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
	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

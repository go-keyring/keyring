//go:build windows

package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestWindowsRoundTrip drives the real Windows Credential Manager through the
// façade. The runner user always has a Credential Manager, so this runs
// unconditionally on the windows lane.
func TestWindowsRoundTrip(t *testing.T) {
	const service = "github.com/go-keyring/keyring test"
	account := fmt.Sprintf("acct-%d", time.Now().UnixNano())
	_ = Delete(service, account)
	t.Cleanup(func() { _ = Delete(service, account) })

	if !Available() {
		t.Fatal("Available() = false on Windows, want true")
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

package keyring

import (
	"errors"
	"testing"
)

// withPresenceVerify swaps the presence-verify seam for the duration of a test.
func withPresenceVerify(t *testing.T, v func() error) {
	t.Helper()
	orig := presenceVerify
	t.Cleanup(func() { presenceVerify = orig })
	presenceVerify = v
}

// okSeams installs backends that store nothing and return a fixed secret from
// Get, recording whether Get reached the backend.
func okSeams(t *testing.T, gotBackend *bool) {
	withSeams(t,
		func(string, string, []byte, config) error { return nil },
		func(string, string) ([]byte, error) { *gotBackend = true; return []byte("secret"), nil },
		func(string, string) error { return nil },
		func() bool { return true },
	)
}

// Get with WithUserPresence runs presenceVerify first, then the backend read.
func TestGetUserPresenceVerifiesThenReads(t *testing.T) {
	verified := false
	reached := false
	okSeams(t, &reached)
	withPresenceVerify(t, func() error { verified = true; return nil })

	got, err := Get("svc", "acct", WithUserPresence())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !verified {
		t.Fatal("WithUserPresence did not run the presence check")
	}
	if !reached || string(got) != "secret" {
		t.Fatalf("backend not read / wrong secret: reached=%v got=%q", reached, got)
	}
}

// A denied presence check fails the read and the secret is never retrieved.
func TestGetUserPresenceDeniedDoesNotRead(t *testing.T) {
	reached := false
	okSeams(t, &reached)
	denied := errors.New("user cancelled")
	withPresenceVerify(t, func() error { return denied })

	_, err := Get("svc", "acct", WithUserPresence())
	if !errors.Is(err, denied) {
		t.Fatalf("Get error = %v, want the denial", err)
	}
	if reached {
		t.Fatal("backend was read despite a denied presence check")
	}
}

// Without the option Get never runs the presence check.
func TestGetWithoutUserPresenceSkipsVerify(t *testing.T) {
	reached := false
	okSeams(t, &reached)
	withPresenceVerify(t, func() error { t.Fatal("presence check ran without WithUserPresence"); return nil })

	if _, err := Get("svc", "acct"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reached {
		t.Fatal("backend not read")
	}
}

// The default presence verifier is a no-op, so on a platform that never installs
// one (darwin — the OS enforces at the item) WithUserPresence reads succeed.
func TestDefaultPresenceVerifyIsNoop(t *testing.T) {
	reached := false
	okSeams(t, &reached)
	// Do NOT override presenceVerify: exercise the package default.
	if _, err := Get("svc", "acct", WithUserPresence()); err != nil {
		t.Fatalf("default presence verify should be a no-op, got %v", err)
	}
}

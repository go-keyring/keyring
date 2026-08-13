package keyring

import (
	"bytes"
	"errors"
	"testing"
)

// withSeams swaps the four backend seams for the given fakes and restores the
// per-GOOS originals afterwards, so the OS-independent dispatch is exercised on
// every platform without a live store.
func withSeams(t *testing.T,
	set func(string, string, []byte, config) error,
	get func(string, string) ([]byte, error),
	del func(string, string) error,
	avail func() bool,
) {
	t.Helper()
	oSet, oGet, oDel, oAvail := backendSet, backendGet, backendDelete, backendAvailable
	t.Cleanup(func() { backendSet, backendGet, backendDelete, backendAvailable = oSet, oGet, oDel, oAvail })
	backendSet, backendGet, backendDelete, backendAvailable = set, get, del, avail
}

func TestDispatchRoundTrip(t *testing.T) {
	store := map[string][]byte{}
	k := func(s, a string) string { return s + "\x00" + a }
	withSeams(t,
		func(s, a string, sec []byte, _ config) error { store[k(s, a)] = sec; return nil },
		func(s, a string) ([]byte, error) {
			v, ok := store[k(s, a)]
			if !ok {
				return nil, ErrNotFound
			}
			return v, nil
		},
		func(s, a string) error { delete(store, k(s, a)); return nil },
		func() bool { return true },
	)

	if err := Set("svc", "acct", []byte("hunter2")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get("svc", "acct")
	if err != nil || !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("Get = %q, %v; want hunter2, nil", got, err)
	}
	if !Available() {
		t.Fatal("Available() = false, want true")
	}
	if err := Delete("svc", "acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestDispatchUnavailable(t *testing.T) {
	withSeams(t,
		func(string, string, []byte, config) error { return ErrUnavailable },
		func(string, string) ([]byte, error) { return nil, ErrUnavailable },
		func(string, string) error { return ErrUnavailable },
		func() bool { return false },
	)
	if err := Set("s", "a", []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Set = %v, want ErrUnavailable", err)
	}
	if _, err := Get("s", "a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get = %v, want ErrUnavailable", err)
	}
	if err := Delete("s", "a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete = %v, want ErrUnavailable", err)
	}
	if Available() {
		t.Fatal("Available() = true, want false")
	}
}

func TestSentinelsDistinct(t *testing.T) {
	if errors.Is(ErrNotFound, ErrUnavailable) || errors.Is(ErrUnavailable, ErrNotFound) {
		t.Fatal("ErrNotFound and ErrUnavailable must be distinct sentinels")
	}
}

// TestSetOptionThreading proves the option resolution in Set reaches the
// backend seam: a plain Set delivers a zero config (userPresence false), and a
// Set with WithUserPresence delivers a config with userPresence set. This
// covers the option plumbing on every platform without a live vault.
func TestSetOptionThreading(t *testing.T) {
	var gotUP bool
	var calls int
	withSeams(t,
		func(_, _ string, _ []byte, cfg config) error { gotUP = cfg.userPresence; calls++; return nil },
		func(string, string) ([]byte, error) { return nil, ErrNotFound },
		func(string, string) error { return nil },
		func() bool { return true },
	)

	if err := Set("svc", "acct", []byte("x")); err != nil {
		t.Fatalf("Set (no option): %v", err)
	}
	if gotUP {
		t.Fatal("plain Set delivered userPresence=true, want false")
	}

	if err := Set("svc", "acct", []byte("x"), WithUserPresence()); err != nil {
		t.Fatalf("Set (WithUserPresence): %v", err)
	}
	if !gotUP {
		t.Fatal("Set(WithUserPresence) delivered userPresence=false, want true")
	}
	if calls != 2 {
		t.Fatalf("backend Set called %d times, want 2", calls)
	}
}

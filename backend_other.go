//go:build !darwin && !windows && !linux

package keyring

// On a platform with no supported secret store, every entry point reports
// [ErrUnavailable] — never a silent success — while the package still builds
// and cross-compiles.
func init() {
	backendSet = func(string, string, []byte, config) error { return ErrUnavailable }
	backendGet = func(string, string) ([]byte, error) { return nil, ErrUnavailable }
	backendDelete = func(string, string) error { return ErrUnavailable }
	backendAvailable = func() bool { return false }
}

package security

import "time"

// OpenTrustStoreForTest opens a store with an injectable clock. Only tests may use it.
func OpenTrustStoreForTest(dir string, expiry time.Duration, now func() time.Time) (*TrustStore, error) {
	return openTrustStore(dir, expiry, now)
}

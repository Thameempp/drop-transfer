package power

import "testing"

func TestKeepAwakeReleaseIsSafe(t *testing.T) {
	release := KeepAwake("test")
	release()
	release() // idempotent
}

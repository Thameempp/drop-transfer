package transfer

import (
	"fmt"
	"time"
)

func fmtSprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

func dataIdleTimeoutForTest(d time.Duration) func() {
	old := dataIdleTimeout
	dataIdleTimeout = d
	return func() { dataIdleTimeout = old }
}

//go:build windows

package power

import (
	"runtime"
	"sync"
	"syscall"
)

const (
	esContinuous     = 0x80000000
	esSystemRequired = 0x00000001
)

func keepAwake(string) func() {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("SetThreadExecutionState")
	stop := make(chan struct{})
	done := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		// The state belongs to the thread that set it, so keep this goroutine on one.
		runtime.LockOSThread()
		defer close(done)
		proc.Call(uintptr(esContinuous | esSystemRequired))
		close(ready)
		<-stop
		proc.Call(uintptr(esContinuous))
	}()
	<-ready
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
		})
	}
}

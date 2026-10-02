//go:build !windows

package power

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

func keepAwake(reason string) func() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		// -i: no idle sleep, -s: no system sleep on AC power, -w: end with us.
		cmd = exec.Command("caffeinate", "-i", "-s", "-w", fmt.Sprint(os.Getpid()))
	case "linux":
		cmd = exec.Command("systemd-inhibit", "--what=idle:sleep", "--who=drop", "--why="+reason, "--mode=block", "sleep", "infinity")
	default:
		return func() {}
	}
	if err := cmd.Start(); err != nil {
		return func() {} // tool not installed: nothing to hold
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
}

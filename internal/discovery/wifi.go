package discovery

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// WiFiName returns the name of the Wi-Fi network this machine is connected to,
// if the operating system will tell a program (macOS often will not). It is
// only used as a friendly label; networks are recognised by their router.
func WiFiName(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out := func(name string, args ...string) string {
		b, _ := exec.CommandContext(ctx, name, args...).Output()
		return string(b)
	}
	switch runtime.GOOS {
	case "darwin":
		for _, ifc := range []string{"en0", "en1"} {
			if n := parseNetworksetup(out("networksetup", "-getairportnetwork", ifc)); n != "" {
				return n
			}
		}
	case "linux":
		if n := strings.TrimSpace(out("iwgetid", "-r")); n != "" {
			return n
		}
		return parseNmcli(out("nmcli", "-t", "-f", "active,ssid", "dev", "wifi"))
	case "windows":
		return parseNetsh(out("netsh", "wlan", "show", "interfaces"))
	}
	return ""
}

func parseNetworksetup(s string) string {
	const p = "Current Wi-Fi Network:"
	if i := strings.Index(s, p); i >= 0 {
		n := strings.TrimSpace(s[i+len(p):])
		if n != "" && !strings.Contains(n, "redacted") {
			return n
		}
	}
	return ""
}

func parseNmcli(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "yes:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "yes:"))
		}
	}
	return ""
}

var ssidRe = regexp.MustCompile(`(?m)^\s*SSID\s*:\s*(.+?)\s*$`)

func parseNetsh(s string) string {
	// "BSSID" lines do not match: the pattern requires the line to start with SSID.
	if m := ssidRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

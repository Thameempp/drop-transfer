# Platforms

| Platform | Built | Run-tested |
|---|---|---|
| macOS (arm64) | yes | yes — two local instances, mDNS, TLS, PIN auth, lockout, text |
| Linux | cross-compiled | no |
| Windows | cross-compiled | no |

Known cross-platform concerns: Windows reserved names and illegal characters are handled in `filesystem.SafeName`; the progress bar and picker use ANSI escapes, which need a VT-capable Windows terminal (untested); mDNS needs UDP 5353 allowed by the host firewall; Windows Defender Firewall will prompt on first `drop receive`. File permission bits and symlinks are not transferred yet.

The masked PIN prompt reads the terminal directly (`/dev/tty`, or `CONIN$` on Windows) so it works with piped stdin; the Windows path is cross-compiled but untested.

## Measured performance (macOS arm64, loopback, one machine, TLS 1.3 + SHA-256 on both ends)
`go test -bench` on this repo: ~190 MB/s for one 256 MiB file; ~24 MB/s for 2,000 × 4 KiB files (per-file overhead dominates; files are sent sequentially). Loopback has no link limit, so these bound what `drop` itself does and say nothing about Wi-Fi/Ethernet speeds. The CLI also waits for discovery (3 s default) before connecting, which dominates wall-clock time for small transfers. These are single runs on one laptop, not a general claim.

Git commands need `git` on `PATH` (developed and tested with Git 2.50; no recent-only features are used, and the empty-tree id falls back to SHA-1 when `rev-parse --show-object-format` is unavailable). Not supported: split-index repositories (`core.splitIndex`) because the private index copy cannot find its shared index; git then reports an error. Windows path handling for Git is cross-compiled but untested.

`drop devices` reads the ARP table straight from the kernel on macOS/FreeBSD (no helper program), from `/proc/net/arp` on Linux, and by running `arp -a` on Windows (untested). Starting from macOS Sequoia, apps may need "Local Network" permission before they can see or talk to devices on the LAN; if `drop devices` finds nothing on a Mac that clearly has neighbors, check System Settings → Privacy & Security → Local Network for your terminal.

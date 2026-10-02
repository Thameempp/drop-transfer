# drop

Developer-first local file transfer. Discover → Select → Transfer → Verify.

```bash
drop main.py
```

`drop` finds nearby devices running `drop receive`, lets you pick one, streams the file, and confirms the receiver computed the same SHA-256. No account, cloud, USB, SMB, SSH, or IP addresses.

> **Status: early.** File, folder and plain-text transfer work over TLS 1.3, authorized by a Drop PIN. Project awareness (detection, `.gitignore`, smart exclusions, secret detection) and Git integration (`drop diff`, `drop git`) work. The security model is documented — and not independently audited — in [docs/security.md](docs/security.md).

## Install

Requires [Go](https://go.dev/dl/) (version in `go.mod`). Git is only needed for `drop diff` / `drop git`.

```bash
git clone <this repository> && cd drop
make install      # builds drop and puts it in a directory that is already on your PATH
drop --version
```

`make install` picks the first writable directory already on your `PATH` from `~/.local/bin`, `~/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, so `drop` works in a new terminal right away. If none qualifies it creates `~/.local/bin` and adds it to your shell startup file (then open a new terminal). Choose the location yourself with `make install BINDIR=/some/dir`; if another `drop` earlier on your `PATH` would shadow the new one, it tells you which.

Or build without installing: `make build` → `./bin/drop` (or `./bin/drop.exe` on Windows). On Windows, run `.\install.bat` (or `make install` if make is installed, or `powershell -ExecutionPolicy Bypass -File scripts\install.ps1`) to automatically build and install `drop.exe` to a directory on your PATH. Do the same on **every** machine that should send or receive.

**Verify it works** on your machine in about 10 seconds (starts two instances locally and exercises a file, a project folder, text, a Git patch, a wrong PIN and lockout):

```bash
make smoke
```

**Network requirements:** both devices on the same LAN/Wi-Fi; mDNS (UDP 5353) and TCP between them must not be blocked (guest Wi-Fi with "client isolation", some VPNs and strict firewalls block this; on Windows allow `drop` through Windows Defender Firewall on first run). If devices don't see each other, `drop receive` prints its port, and you can bypass discovery with `drop --to <ip>:<port> file`.

## Quick start

On the receiving machine (first run prints a one-time **Drop PIN**):

```bash
drop receive            # asks before accepting each file; saves to ~/Downloads
```

On the sending machine:

```bash
drop main.py                      # pick a device, enter the PIN, done
drop .                            # a project: junk and secrets are left out, and shown to you
drop --dry-run .                  # see exactly what would be sent and excluded
drop --to windows main.py         # skip the menu (PIN from the prompt or $DROP_PIN)
echo "hello" | drop --text        # plain text: no PIN by default
```

```text
Nearby Devices            Enter Drop PIN:           ✓ Authenticated
❯ Windows-PC              > ******                  Sending main.py → Windows-PC
  MacBook                                           ✓ SHA-256 verified
```

If a file with the same name exists, the receiver renames the new one (`main (1).py`) unless you choose Replace. An existing folder is never merged into or replaced: the new one is saved as `src (1)`. Nothing is overwritten silently.

### Folders and projects

Folders are scanned first and you are told what will be sent and what will not:

```text
Project detected: pdf-assistant (Git, Python)

  Transferable: 186 MB (1,506 files, 6 folders)
  Excluded:     3.1 GB (20,055 files)
    .git/                       210 MB  Git history
    .venv/                      820 MB  virtual environment
    node_modules/               1.7 GB  dependencies

⚠ Potential sensitive files detected and excluded:
    .env  (environment file)
    config/credentials.json  (cloud credentials file)
  Detection is a safety net, not a guarantee: other secrets may still be sent.
```

- **Project detection** looks only at the folder you name (`.git`, `go.mod`, `package.json`, `pyproject.toml`, `requirements.txt`, `Cargo.toml`, `pom.xml`, `build.gradle`, `Makefile`, …). A `README.md` alone does not make a folder a project.
- **In a project**, `.git/`, anything matched by `.gitignore` (including nested ones and `.git/info/exclude`) and generated folders (`node_modules`, `.venv`/virtualenvs, `__pycache__`, `dist`, `build`, `target` for Rust/Java, `coverage`, caches) are left out.
- **Secrets are excluded in every folder transfer**: `.env*` (not `.env.example`), `*.pem`, `*.key`, `id_rsa`, `credentials.json`, service-account files, `.netrc`, `.ssh/`, `.aws/`, … and small text files containing well-known credential formats (private key blocks, AWS, GitHub, Slack, Stripe, Google, Anthropic and OpenAI keys). Reasons never include the secret itself.
- **Nothing is hidden**: the summary lists the largest exclusions; `--explain` lists all of them; `--dry-run` shows the plan and stops without connecting. If everything would be excluded, `drop` stops with exit code 2.
- **Overrides**: `--include-secrets` sends files that look like secrets (it says so loudly); `--all` turns the project rules off (sends `node_modules`, `.git`, ignored files) but still excludes secrets unless combined with `--include-secrets`. Naming a single sensitive file (`drop .env`) sends it, with a note.
- Symbolic links are never followed or copied (they are listed), empty folders are kept, and the executable bit is preserved. Every file is verified individually and the whole tree end to end; a folder is only moved into place after all of it verified. An existing folder is never merged into or replaced: the new one is saved as `src (1)`.

### Git: `drop diff` and `drop git`

```text
Git changes: pdf-assistant (feature/mcq)

  Modified:
    src/parser.py
    src/retriever.py

  Added:
    tests/test_rag.py
    new file.txt  (untracked)

  Deleted:
    old_loader.py

  Renamed:
    a.py → b.py

⚠ Withheld because they look sensitive:
    .env  (environment file)

❯ Send patch
  Send changed files
```

- `drop diff` sends your uncommitted work (staged, unstaged and untracked) either as a **patch** (`--patch`; the receiver runs `git apply name.patch`, deletions, renames, binary files and mode changes included) or as just the **changed files** in their folders (`--files`; deleted files can't be sent this way). `--staged` limits it to what you have `git add`ed; `--dry-run` shows the summary and stops.
- `drop git` sends the repository itself as a **bundle** with full history of the current branch (`--all` for every branch and tag); the receiver runs `git clone name.bundle`. Uncommitted work is not included. If the history contains files that look like secrets (even ones deleted later) it asks first; non-interactively it refuses unless `--include-secrets`.
- **drop never modifies your repository**: no staging, commits, checkouts or config changes, and not even the index refresh that `git diff` normally performs. It works on a private copy of the index, and this is tested by hashing `.git` before and after.
- Secret protection applies here too: changed files that look like secrets are withheld from the patch and from the files, with the reason shown (`--include-secrets` overrides).
- Requires Git on `PATH`. All sends need the Drop PIN. If a file is named `diff` or `git`, write `drop ./diff`.

### Seeing who is on your network: `drop devices`

```text
NAME           ADDRESS       DROP         DETAILS
Windows-PC     192.168.1.20  ready        windows, trusts you
dsldevice.lan  192.168.1.1   not running  unidentified device
Android        192.168.1.5   not running  phone/tablet or privacy-MAC device
LivingRoom-TV  192.168.1.31  not running  AirPlay, Apple device
192.168.1.8    192.168.1.8   not running  phone/tablet or privacy-MAC device

1 device ready to receive, 4 devices without drop running. Run `drop receive` on a device to send to it.
```

It lists devices on your local network **whether or not they run drop**, with drop-ready ones first. To send to a device it must run `drop receive`; the list tells you who is there and who is ready (`--ready` shows only ready devices, which is what the send menu uses).

How it finds them, and what to expect:
- **mDNS/Bonjour:** every service type a device advertises (AirPlay, printers, SSH, file sharing, ...).
- **The OS neighbor (ARP) table**, filled first by sending **one 1-byte UDP packet to each address of your own subnet** (at most a /24). Use `--passive` to skip that; then only devices you recently talked to show up.
- **Names** from reverse mDNS, NetBIOS (Windows/Samba) and reverse DNS, in that order.
- **Limits:** a device that advertises nothing, answers none of the name lookups and sleeps its Wi-Fi may be missing or shown by IP only. Many phones use a random MAC per network and say nothing, so they show as "phone/tablet or privacy-MAC device". Only your local subnet is scanned, and nothing is stored or sent anywhere. Guest networks with client isolation hide everything. Results can differ run to run as devices sleep and wake.

### Trusted devices (skip the PIN)

After a PIN-authorized transfer, the **receiver** is asked once:

```text
Trust MacBook-Pro for future transfers? It will no longer need the PIN.
  (device key A4:91:7C:…; revoke any time with `drop security untrust`) [y/N]
```

If you answer yes, that device can send without a PIN from then on, and its menu entry shows `✓ Trusted`:

```text
Nearby Devices
❯ Windows-PC  (windows)  ✓ Trusted
  Ubuntu      (linux)
```

Trust is bound to the sender's **cryptographic key**, never to the PIN (which is not stored anywhere): the receiver keeps the sender's public key, and TLS proves the sender holds the matching private key. A different device using the same name gets nothing. The receiver still confirms each transfer (and `--yes` never creates trust). Trust expires after 90 days **unused** (use refreshes it; `trust_expiry_days`, `0` = never). Manage it with `drop security trusted` and `drop security untrust <name>` / `--all`; revocation takes effect immediately, even in a running `drop receive`. Changing the PIN does not revoke trusted devices: review them if the old PIN was exposed.

## Security in one minute

| | |
|---|---|
| Discovery | shows nearby devices |
| **PIN** | **authorizes** protected transfers; verified without ever being sent (PAKE), stored only as an Argon2id hash |
| TLS 1.3 | **encrypts** everything, always; there is no plaintext mode |
| SHA-256 | verifies integrity |

The PIN is not an encryption key. 3 wrong PINs lock the receiver for 30 s (doubling). Plain text skips the PIN by default (`[security] text_requires_pin`); files, folders, projects, Git and clipboard always require it. Details and limits: [docs/security.md](docs/security.md).

## Commands

| Command | Purpose |
|---|---|
| `drop diff` / `drop git` | Send Git changes (patch or files) / the repository as a bundle |
| `drop <path>` / `drop send <path>` | Send a file, or a folder/project (`--dry-run`, `--explain`, `--include-secrets`, `--all`) |
| `drop receive [--dir D] [--port N] [--yes] [--once]` | Accept incoming files |
| `drop --text` / `drop send --text` | Send plain text from stdin |
| `drop security [set-pin\|generate-pin\|trusted\|untrust\|status]` | Manage the Drop PIN and trusted devices |
| `drop devices [--ready] [--passive]` | List **everything** on your network, and which devices are ready to receive with drop |
| `drop status` | Show identity, fingerprint, PIN status, config paths |

If a file is named like a subcommand (`send`, `status`…), write `drop ./send`.

Exit codes: `0` ok · `1` general · `2` usage · `3` device unavailable · `4` PIN rejected / locked / authentication failed · `5` transfer failed/declined · `6` verification failed · `130` cancelled.

Progress and prompts go to stderr; stdout carries only results, so output pipes cleanly. Output uses no colour.

## Configuration

Optional `config.toml` in the config dir (`os.UserConfigDir()/drop`, or `$DROP_HOME`):

```toml
[device]
name = "my-laptop"      # default: hostname

[transfer]
receive_dir = "/home/me/inbox" # absolute path (no ~ expansion); default: ~/Downloads

[security]
text_requires_pin = false      # default
max_attempts = 3               # failed PINs before lockout
lockout_seconds = 30           # doubles each lockout
lockout_max_seconds = 3600
trust_expiry_days = 90         # unused trusted devices need the PIN again (0 = never)
pin_length = 6                 # for generated PINs (6-12)
```

## Architecture

```
cli → transfer (sender/receiver) → protocol (framing/messages) → security (TLS 1.3, PIN auth) → transport (TCP) → network
                 discovery (mDNS) · device (identity) · filesystem (path safety) · config
```

See [docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md).

## Roadmap

Done: identity, mDNS discovery, TCP transport, versioned handshake, streaming file transfer, SHA-256 verification, receive confirmation, safe naming/conflicts, folder transfer with manifest and per-file/tree verification, project detection, `.gitignore` and smart exclusions, secret detection, Git changes and bundles, trusted devices, TLS 1.3 encryption, PIN authorization with brute-force lockout, plain-text mode.

Next, in order: temporary PINs · QUIC · resume/chunking/compression · clipboard, stdin, history, `doctor` · mobile clients.

## Development

```bash
go build ./... && go vet ./... && go test -race ./...
```

See [docs/development.md](docs/development.md) and [docs/testing.md](docs/testing.md).

## License

MIT

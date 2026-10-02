# Security

Four separate mechanisms, each with one job:

| Layer | Question it answers | Mechanism |
|---|---|---|
| Discovery (mDNS) | Which devices are nearby? | `_drop._tcp` advertisement: ID, name, OS, versions. No secrets. |
| **Drop PIN** | **Who may send protected content to this device?** | PAKE (CPace) inside the TLS channel; Argon2id verifier on the receiver |
| Secure transport | Who can read the data in transit? | TLS 1.3, ed25519 device certificates |
| SHA-256 | Did the bytes arrive intact? | Hash computed independently by both sides |

**The PIN authorizes transfers. It is not an encryption key.** Encryption comes from TLS regardless of the PIN.

## Flow
```
select device → enter PIN → TLS 1.3 handshake → PIN authorization (PAKE) → request → receiver approval → data → SHA-256 check
```
Nothing is written to disk before the sender is authorized and the receiver has approved.

## Device identity
Each install has an ed25519 key (`identity.json`, mode 0600, never transmitted). The device ID is the first 16 bytes of SHA-256 of the public key, so it cannot be claimed without the key. Every TLS connection is mutually authenticated with certificates built from these keys, and the `device_id` in the protocol hello must match the certificate. When the target came from discovery, the sender pins that ID: a different device answering for a selected name is refused. Names, IPs and MACs are never used for authentication.

## The PIN
- Default: 6 random digits, generated on first `drop receive` and shown **once**. 6–12 digits supported (`pin_length`). Change with `drop security set-pin` / `generate-pin`; changing it invalidates the old PIN and clears lockout state.
- Stored only as an **Argon2id** verifier in `pin.json` (mode 0600): salt, cost parameters (t=3, m=64 MiB, p=4) and hash. Never in config, logs, history, discovery or transfer metadata.
- **Never sent over the network, not even inside TLS.** The sender derives a password from the PIN with the receiver's Argon2 salt/parameters, and both sides run **CPace** (`filippo.io/cpace`, ristretto255), a password-authenticated key exchange, *inside* the TLS session. CPace is bound to that session via the TLS exporter (RFC 5705) and to both device IDs. Explicit key confirmation (HMAC-SHA-256 under an HKDF-expanded key, role-labelled) is exchanged, so authentication is **mutual**: the sender also learns the receiver really knew the verifier.
- **Why a PAKE and not "send the PIN over TLS"?** The TLS certificates are self-signed, so nothing proves the receiver is who the sender thinks. An active man-in-the-middle could terminate TLS, read a PIN sent through it, and reuse it. With the PAKE, a relaying attacker's two TLS sessions have different exporter values, the keys differ, and authentication fails (tested). A wrong guess reveals nothing beyond "no": one online guess per attempt.
- Wrong PINs return only `Incorrect Drop PIN` plus attempts remaining. Nothing indicates how close a guess was (tested). The comparison is constant-time.

## Brute-force protection
Counted across **all** peers (an attacker controls their address): 3 failed attempts, then lockout for 30 s, doubling per lockout up to 1 h (`max_attempts`, `lockout_seconds`, `lockout_max_seconds`). An attempt is counted when it **starts** and refunded only on success, so probing and hanging up still counts. State persists in `auth_state.json`; restarting the receiver does not reset it, and a corrupt file fails closed (locked). While locked, even the correct PIN is refused. Trade-off: someone on the LAN can deliberately lock you out; the lockout also protects against 10^6-guess brute force, which would otherwise be feasible.

## Which transfers need the PIN
One central policy (`security.Policy.RequiresAuthorization`), enforced by the **receiver** (a modified sender cannot skip it):

| Type | PIN |
|---|---|
| file, **folder**, project, git, clipboard, anything unknown | required |
| plain text | not required by default (`text_requires_pin = false`) |

Plain text still travels over TLS and still needs the receiver's consent; it is limited to 1 MiB, held in memory, never written to disk, and sanitised of terminal control sequences before display. Set `text_requires_pin = true` to protect it too. Clipboard is protected by policy; the clipboard feature itself does not exist yet.

## No plaintext fallback
The receiver refuses to run without a TLS upgrade, the sender refuses to send on a connection that is not authenticated and encrypted, and the protocol version was bumped to 2 so early unauthenticated peers cannot interoperate. There is no development bypass flag.

## Folder transfers
A folder manifest is attacker-controlled input from an authorized peer. The receiver validates all of it before creating a single file (see docs/protocol.md): path traversal, absolute and drive paths, backslashes, NUL, reserved Windows names, duplicates and case/character collisions, undeclared parents, file/directory confusion, entry/depth/size limits, and agreement with the announced summary. Data goes into a private staging folder (exclusive-create, never following or creating symlinks) and is renamed into place only after every file and the whole-tree hash verify, so a failed or malicious transfer leaves nothing behind. Existing folders are never merged into or replaced. On the sender side, symlinks are never followed or copied (and are reported), a file swapped for a symlink after the scan is refused, and a file that changes while being sent aborts the transfer. A stalled sender cannot hold the receiver beyond a 2-minute idle timeout.

### Secret detection (a safety net, not a guarantee)
Folder transfers exclude likely secrets by default so that `drop .` does not ship `.env` files and keys by accident: by file name (`.env*` except templates, `*.pem`, `*.key`, `id_rsa`..., `credentials.json`, service-account files, `.netrc`, `.tfstate`, ...), by sensitive folder (`.ssh/`, `.aws/`, `.gnupg/`, ...), and by content for text files up to 1 MiB (private key blocks and AWS, GitHub, Slack, Stripe, Google, Anthropic, OpenAI key formats). The documented AWS example key is not flagged. Findings report only the kind of secret, never its value. **It will miss secrets** (custom formats, encoded or split values, secrets in large or binary files, passwords in config) and can flag harmless files such as test fixtures. `--include-secrets` disables it. A single file you name explicitly is sent (with a note), because that is an explicit choice.

Limitations: executable bits are preserved but no other permissions, ownership, timestamps or extended attributes; Unicode normalisation differences (macOS NFD vs NFC) are not detected as collisions; no free-disk-space check; no total-size limit.

## Git
- **Read-only.** `drop` runs `git` with no shell (argument slices only), `GIT_LITERAL_PATHSPECS=1` (a file named `*.txt` is a file, not a glob), `GIT_OPTIONAL_LOCKS=0`, no external diff/textconv helpers, `core.fsmonitor=false`, and, most importantly, **against a private copy of the index** (`GIT_INDEX_FILE`). Porcelain `git diff` rewrites `.git/index` (a stat-cache refresh) even with `GIT_OPTIONAL_LOCKS=0`, so isolating the index makes "never modifies the repository" structural. The copy keeps the original's modification time, because git decides whether cached file stats can be trusted by comparing them to the index file's own mtime. Untracked files are diffed with `--no-index` rather than `git add -N`. A test hashes the whole `.git` directory before and after every operation and fails if isolation is removed.
- **Secrets.** Changed files whose path (or any parent folder, or rename source) looks sensitive, or whose current content matches a known credential format, are withheld from patches and file sends. Limits: a modified file's *old* lines appear in patch context, and only the *working copy* is content-scanned (for `--staged`, the staged version can differ); deleted files are screened by name only.
- **Bundles carry history.** A bundle contains every commit of the branch, so a secret committed once and removed later is inside it. `drop git` scans every path ever added in the sent history by name (not content), and asks before sending, or refuses non-interactively without `--include-secrets`. It cannot detect secrets inside file contents of old commits.
- **Untrusted repositories.** Running git commands in a repository you do not trust can execute configuration it contains; `drop` disables the known helper hooks listed above, but only use `drop diff`/`drop git` in repositories you would run `git status` in.

## Network discovery and scanning
`drop devices` is **active** on your own network: it sends mDNS queries (multicast), one 1-byte UDP datagram to UDP port 9 of each address in your local /24 (so the OS resolves each address and fills its ARP table; skip with `--passive`), mDNS reverse-lookup queries, and a NetBIOS name-status query (UDP 137) and a reverse-DNS query per unnamed device. This only touches your directly attached private subnets (a larger subnet is clipped to the /24 around your address), uses small single packets, and never connects to a service or sends file data. Results are shown to you and not stored. Be aware that some networks treat probing as noise, and that discovery reveals nothing about a device beyond what it answers publicly. A device appearing in the list is **not** authorization to send to it: that still requires `drop receive` on the other side, TLS, and the PIN or trust.

## Other protections
Integrity (SHA-256, mismatch discards the file, exit 6); consent prompt per transfer; destination safety (`SafeName`, `O_EXCL`, no symlink following, atomic rename after verification); terminal-injection filtering of peer-supplied names; 1 MiB control-frame cap; handshake/auth deadlines; PIN and keys never logged (tested).

## Threat model and limitations
- **Protected against:** passive eavesdroppers; active MITM on the LAN (cannot learn or relay the PIN); unauthorized devices writing files; remote brute-forcing of the PIN; replay of recorded auth messages.
- **Not protected against:** an attacker who steals `pin.json`. The verifier is the PAKE password: it lets them impersonate the receiver and, because a 6-digit PIN has only 10^6 values, recover the PIN offline (Argon2id makes each guess cost ~64 MiB and tens of ms, not impossible). Treat the file as a credential. A longer PIN helps.
- Anyone who knows the PIN can send to this device: the PIN is a shared secret, not per-sender. Rotate it if shared widely. Trusted devices are per-sender and revocable.
- A LAN attacker can cause lockouts (denial of service).
- Unauthenticated peers can complete a TLS handshake and receive the protocol hello/ack before authorizing; this reveals device name/OS only.
- No free-space or total-size limit on accepted files yet.
- The CPace library is a 2021 reference implementation by a well-known cryptographer, not independently audited, and TLS identities are not yet persisted as a trust anchor. No independent audit of `drop` has been done.
- `identity.json`/`pin.json` protection on Windows relies on user-profile ACLs.

## Trusted devices
A receiver can remember a sender so it no longer needs the PIN. This is an identity mechanism, not a stored credential:

- **What is stored.** On the receiver, `trusted.json` (0600) holds each trusted device's **public key**, name, OS, and added/last-used times. The PIN (or anything derived from it) is not involved and is not stored. On the sender, `trusted_by.json` holds only a hint of which receivers trust it, used to skip the PIN prompt and label the menu; the receiver is the authority, so a stale hint just falls back to the PIN.
- **How trust is created.** Only when all of these hold: the sender just proved the PIN on that connection, the receiver's user answered yes to the offer, and the transfer then verified. It is never created from a PIN-less session (plain text), never by `--yes`, and never from an already-trusted session. Declined or failed transfers create nothing.
- **How trust is used.** The receiver tells a connecting sender in the hello reply that it recognizes the TLS-verified key; the sender then skips the PIN exchange. Identity comes from the mutually authenticated TLS handshake, so the sender must hold the private key; a device with the same name, or a forged `device_id`, is not trusted. Trusted use never touches the lockout counters, and the receiver still asks for consent per transfer.
- **Expiry and revocation.** Trust lapses after 90 days without use (`trust_expiry_days`, sliding: each use refreshes it, written back at most once an hour; `0` disables). `drop security untrust` revokes one or all immediately: the store re-reads its file on every lookup, so a running `drop receive` notices; a corrupt or deleted file fails closed (nobody trusted); hand-edited entries whose ID does not match their key are rejected.
- **Risk.** Whoever steals a trusted device's `identity.json` can send to every receiver that trusts it, without a PIN, until revoked or expired. Protect identity files like SSH keys. Trusted devices also stay trusted when the PIN changes (they do not depend on it); after a suspected PIN leak, review `drop security trusted`.
- **Limits.** Trust is per device, all-or-nothing (no per-type or per-folder scoping); the sender-side hint is unauthenticated (it can only cause an extra round trip, never grant access).

## Future: temporary PINs (designed for, not built)
A temporary PIN (`drop pin`, expiring, single-use) would be a second verifier source consulted by the same `Authenticator` and the same `Limiter`.

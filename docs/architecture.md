# Architecture

Layers, top to bottom; each knows only the one below it.

| Package | Responsibility |
|---|---|
| `internal/cli` | Commands, flags, prompts, progress bar, device picker, exit codes. The only package that touches the terminal. |
| `internal/transfer` | Sender and Receiver state machines: handshake, request, approval, streaming, verification, atomic placement. Takes a `transport.Conn`; reports progress via callbacks. |
| `internal/protocol` | Versioned control messages and framing. |
| `internal/security` | TLS 1.3 upgrade of any `transport.Conn` (device-certificate identity, channel binding), PIN verifier (Argon2id), attempt limiter, trusted-device store (public keys; revocation re-read on every lookup), CPace-based PIN authorization (`Authenticate` / `Authenticator`), and the central authorization `Policy`. The transfer layer sees only an authenticated, encrypted `transport.Conn` (`Peered`). |
| `internal/transport` | `Transport`/`Listener`/`Conn` interfaces; `TCP` implementation. QUIC will be another implementation. |
| `internal/discovery` | Two layers: advertising/finding drop peers over mDNS (`_drop._tcp`, used by send and receive), and `ScanLAN`, a general view of the network (mDNS service enumeration, kernel/OS neighbor table, name lookups) used by `drop devices`. The send menu only uses the first layer. |
| `internal/device` | Persistent ed25519 identity, device ID, fingerprint. |
| `internal/filesystem` | Name validation, race-safe unique-name reservation/rename, and the symlink-safe directory scanner. |
| `internal/project` | Project detection, a git-compatible `.gitignore` matcher, generated-directory rules, and secret detection. Implements `filesystem.Rules`, so the scanner stays generic. |
| `internal/git` | Read-only repository access through the `git` CLI: status/changes, patches, bundles, history scan. Every command runs against a private copy of the index with a hardened environment. |
| `internal/config` | Config file and platform directories (`DROP_HOME` override for tests / multiple local instances). |

Design choices
- `transfer` never imports `cli` or a concrete transport, so it is testable over loopback TCP and reusable by future IDE/mobile front-ends.
- The receiver decides via an `Approver` interface; the CLI supplies a prompt, tests supply functions.
- Project awareness is a `filesystem.Rules` plug-in: the scanner asks it about every entry (parents first), prunes excluded directories, and records each exclusion with a category, reason and measured size so the CLI can show all of it. The wire protocol is unchanged: excluded files simply are not in the manifest.
- Git adds no wire format: a patch or bundle is an ordinary file transfer, "changed files" is a folder transfer built from an explicit path list (`filesystem.NewScanFromPaths`). The CLI classifies them as `git` for policy purposes (PIN required) but dispatches on what is actually sent.
- Folders: the sender scans (`filesystem.Scan`) → `Manifest` → streams each file once with a hash trailer; the receiver validates the manifest (`ParseManifest`) before writing, stages into a private directory, and renames atomically at the end. Both sides compute a tree hash for end-to-end verification.
- Incoming data is written to a hidden `.drop-partial-*` file in the destination and renamed into place only after the SHA-256 matches, so a failed transfer never leaves a file under its real name.
- Security is injected: the receiver takes an `Upgrade` hook, an `Authenticator` and a `Policy`; the sender is handed an already-secured connection. `transfer` still never imports TLS or the CLI, and QUIC can later supply its own authenticated streams. There is no plaintext mode: the receiver refuses to run without `Upgrade`, the sender refuses a non-`Peered` connection.
- Authorization has two sources, both decided in the receiver: a PIN proven on this connection, or a trusted key recognized by the TLS identity. Either yields `Incoming.Authorized` (with `AuthMethod`), and `security.Policy` then gates each transfer type.
- Authorization is decided in one place (`security.Policy`) and enforced by the receiver, not scattered through the CLI.
- Packages from the original plan that have no code yet (`project`, `git`, `clipboard`, `history`) are deliberately not created until their phase.

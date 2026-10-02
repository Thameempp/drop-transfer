# Protocol (version 2)

Language-independent description so other clients (e.g. mobile) can implement it. Version 1 was an unauthenticated prototype and is not supported.

## Discovery
DNS-SD service `_drop._tcp.local.`, instance name = device ID, port = receiver TCP port. TXT: `id` (hex, 32 chars: first 16 bytes of SHA-256 of the ed25519 public key), `name`, `os`, `v` (comma-separated supported protocol versions). No secrets. Devices are identified by `id`, never by address.

## Secure channel
Immediately after TCP connect, before any control message: **TLS 1.3**, mutual authentication, self-signed ed25519 certificates (client certificate required). Peer identity = device ID derived from the certificate key. Non-TLS connections are rejected. Chain validation is not used; the dialer MAY pin the expected device ID from discovery and MUST abort on mismatch.

## Framing
4-byte big-endian length `N` (1 ≤ N ≤ 1 MiB) + `N` bytes of UTF-8 JSON `{"type": "...", "body": {...}}`. File and text content is **raw bytes**, not framed.

## Flow
```
dialer                                      listener
  hello{versions,device_id,device_name,os} →                (device_id MUST equal the TLS-derived ID)
                      ← hello_ack{version,device_id,device_name,os,trusted?}

  [protected transfers, unless hello_ack.trusted] PIN authorization:
  auth_init →
                      ← auth_params{salt,time,memory_kib,threads} | {locked:true,retry_after_secs}
  auth_start{msg} →
                      ← auth_challenge{msg}
  auth_proof{tag} →
                      ← auth_result{ok,tag,attempts_remaining,retry_after_secs}

  transfer_request{transfer_id,mode:"file"|"text"|"folder",name?,size,sha256,files?,dirs?} →
                      ← transfer_response{accept,reason?}
  [if accepted] exactly `size` raw bytes →
                      ← transfer_result{ok,sha256,error?}
```
Version negotiation: highest common version. Either side may send `error{message}` before closing.

### Trusted devices
`hello_ack.trusted` is true when the listener's trust store contains the dialer's TLS-verified public key (unexpired). The dialer then skips the PIN exchange, and the listener treats the connection as authorized (it still decides per request, and still asks its user). If it is false and the dialer has no PIN, the dialer aborts before sending any request. `transfer_result.trusted` is true when, during this transfer, the listener's user chose to trust the dialer (only possible after a successful PIN exchange and a verified transfer); the dialer may then remember that this listener trusts it. Both fields are optional and additive, so protocol version 2 peers without them interoperate (they simply never skip the PIN).

### PIN authorization
- `password = hex(Argon2id(PIN, salt, time, memory_kib, threads, 32 bytes))`. Dialers MUST reject parameters outside sane bounds (time ≤ 10, memory ≤ 256 MiB, threads ≤ 16).
- PAKE: **CPace on ristretto255** (`filippo.io/cpace`): `Start(password, ctx)` → `msg` (48 bytes) → `Exchange` → `msg` (32 bytes) → `Finish`. Context: idA = dialer device ID, idB = listener device ID, ad = `TLS-exporter(label "EXPORTER-drop-pin-auth-v1", 32 bytes) ‖ "drop-pin-auth-v1"`.
- Key confirmation: `tag(role) = HMAC-SHA256(HKDF-Expand(SHA256, key, "drop confirm " ‖ role), msgA ‖ msgB)`, `role` = `initiator` (dialer, in `auth_proof`) or `responder` (listener, in `auth_result`). Each side verifies the other's tag in constant time; the dialer MUST abort if the responder's tag is wrong.
- The PIN is never transmitted. The listener counts the attempt when `auth_init` arrives and refunds it only on success.
- A listener enforces policy itself: if the mode requires authorization (everything except `text`, unless configured) and no successful authorization occurred on the connection, it replies `transfer_response{accept:false}` and writes nothing.

### Receiver rules for `transfer_request`
- `file`: `name` is a bare file name. Receivers MUST reject `/` or `\`, `.`/`..`, drive prefixes, NUL, invalid UTF-8, and SHOULD replace characters illegal on Windows.
- `folder`: `name` is the folder's base name (validated like a file name), `size` the total bytes of all files, `files`/`dirs` the counts, `sha256` the SHA-256 of the manifest blob. See "Folders" below.
- `text`: `size` ≤ 1 MiB; held in memory; never written to disk.
- Unknown modes (including `clipboard`, `folder`, ... until implemented) MUST be rejected; they are never treated as less protected.
- The dialer MUST treat the transfer as failed unless `transfer_result.ok` and its `sha256` equals its own.

## Folders
After `transfer_response{accept:true}` for mode `folder`:
```
dialer                                         listener
  manifest blob (8-byte BE length ‖ JSON) →                (≤ 64 MiB; hash must equal request.sha256)
                      ← manifest_ack{ok,error?}            (nothing has been written yet)
  for each file in manifest order: size raw bytes ‖ 32-byte SHA-256 of those bytes →
                      ← transfer_result{ok,sha256}         (sha256 = tree hash)
```
Manifest: `{"entries":[{"p":"src/main.py","s":42,"x":true},{"p":"src","d":true}, ...]}` — `p` relative path with `/` separators, `d` directory, `s` size, `x` executable. No unknown fields. Parents precede children; directories carry no data. Symlinks and special files are not transferred (the sender reports them). Files excluded by project rules or secret detection are simply absent: the protocol has no notion of them, and the receiver cannot tell they existed.

The listener MUST validate the whole manifest before creating anything: every component must pass the file-name rules above (so `..`, absolute paths, `\`, drive prefixes, NUL are rejected; characters illegal on Windows become `_`); no duplicates, including names that collide case-insensitively or after that substitution; every parent declared earlier; a path cannot be both file and directory; sizes ≥ 0; at most 500 000 entries, depth 64, path length 1024; and counts/total size must equal the request summary. Violations → `manifest_ack{ok:false}` and nothing is created.

Files are written into a private staging folder with exclusive-create, each verified against its trailer; only after every file and the tree hash verify is the staging folder renamed into place. An existing folder of the same name is never merged or replaced: the new one is saved as `name (1)`.

Tree hash = SHA-256 over, for each entry in manifest order, `D\0path\n` (directory) or `F\0path\0size\0hex(sha256)\n` (file), using the sender's original paths. The dialer MUST fail the transfer unless the listener's `transfer_result.sha256` equals its own.

The listener bounds idle time during data (2 minutes without a byte aborts and cleans up).

## Not yet defined
Chunking/resume, clipboard payloads, trusted-device tokens.

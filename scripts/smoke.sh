#!/bin/sh
# End-to-end smoke test of the real binary: two drop instances on this machine
# with separate identities. Exercises discovery, TLS, PIN authorization, a file,
# a folder/project (with exclusions), text, a Git patch, trusted devices, a wrong
# PIN, and lockout. Exits non-zero on the first failure.
#
#   sh scripts/smoke.sh [path/to/drop]
set -u
BIN=$(cd "$(dirname "${1:-bin/drop}")" && pwd)/$(basename "${1:-bin/drop}")
[ -x "$BIN" ] || { echo "binary not found: $BIN (run: make build)"; exit 2; }

T=$(mktemp -d "${TMPDIR:-/tmp}/drop-smoke.XXXXXX")
RECV_PID=""
cleanup() { [ -n "$RECV_PID" ] && kill "$RECV_PID" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT INT TERM

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
check() { # check "description" command...
  d=$1; shift
  if out=$("$@" 2>&1); then ok "$d"; else bad "$d" "$out"; fi
}

mkdir -p "$T/a" "$T/b" "$T/inbox" "$T/work"
printf '[device]\nname = "smoke-recv"\n' > "$T/b/config.toml"
printf '[device]\nname = "smoke-send"\n' > "$T/a/config.toml"
SEND() { DROP_PIN="$PIN" DROP_HOME="$T/a" "$BIN" "$@"; }

echo "drop smoke test ($("$BIN" --version 2>&1 | head -1))"

# A leftover receiver (e.g. from an interrupted run) would make "--to smoke-recv" ambiguous.
if command -v pgrep >/dev/null 2>&1 && pgrep -f "drop-smoke\." >/dev/null 2>&1; then
  echo "a previous smoke run left a drop process behind; stop it first: pkill -f drop-smoke"; exit 2
fi

# --- receiver, first run creates a PIN -------------------------------------
# Launch the binary itself (not through a shell function) so $! is its PID and
# cleanup really stops it.
DROP_HOME="$T/b" "$BIN" receive --yes --dir "$T/inbox" >"$T/recv.out" 2>"$T/recv.err" &
RECV_PID=$!
i=0; while [ $i -lt 40 ] && ! grep -q "ready to receive" "$T/recv.err" 2>/dev/null; do sleep 0.25; i=$((i+1)); done
PIN=$(grep -o '[0-9]\{6\}' "$T/recv.err" | head -1)
if [ -n "$PIN" ]; then ok "receiver started and generated a 6-digit PIN"; else bad "receiver start" "$(cat "$T/recv.err")"; exit 1; fi
sleep 3   # let mDNS announce

# --- discovery ----------------------------------------------------------------
if DROP_HOME="$T/a" "$BIN" devices --timeout 4s 2>&1 | grep -q smoke-recv; then ok "discovery lists the receiver"; else bad "discovery"; fi

# --- file -----------------------------------------------------------------------
head -c 3000000 /dev/urandom > "$T/work/big.bin"
check "send a 3 MB file" SEND --to smoke-recv "$T/work/big.bin"
cmp -s "$T/work/big.bin" "$T/inbox/big.bin" && ok "file arrived byte-identical" || bad "file content differs"

# --- text (no PIN) ---------------------------------------------------------------
if printf 'hello text\n' | DROP_HOME="$T/a" "$BIN" --to smoke-recv --text >/dev/null 2>&1; then ok "plain text without a PIN"; else bad "text"; fi
sleep 0.5; grep -q "hello text" "$T/recv.out" && ok "receiver printed the text" || bad "text not received"

# --- project folder with exclusions ----------------------------------------------
P="$T/work/myproj"; mkdir -p "$P/src" "$P/node_modules/dep" "$P/.git"
echo 'package main' > "$P/main.go"; echo 'module x' > "$P/go.mod"; echo 'x' > "$P/src/a.go"
echo 'dep' > "$P/node_modules/dep/index.js"; echo 'ref' > "$P/.git/HEAD"
echo 'API_KEY=hunter2' > "$P/.env"; echo 'API_KEY=' > "$P/.env.example"
check "send a project folder" SEND --to smoke-recv "$P"
R="$T/inbox/myproj"
[ -f "$R/main.go" ] && [ -f "$R/src/a.go" ] && [ -f "$R/.env.example" ] && ok "source files and .env.example arrived" || bad "project files missing"
if [ ! -e "$R/.env" ] && [ ! -e "$R/node_modules" ] && [ ! -e "$R/.git" ]; then ok ".env, node_modules and .git were NOT sent"; else bad "excluded files were sent"; fi
if ! grep -rq hunter2 "$T/inbox" 2>/dev/null; then ok "no secret content reached the receiver"; else bad "secret leaked"; fi

# --- git patch -------------------------------------------------------------------
if command -v git >/dev/null 2>&1; then
  G="$T/work/repo"; mkdir -p "$G"
  ( cd "$G" && git init -q && echo one > f.txt && git add f.txt \
    && git -c user.email=s@s -c user.name=s -c commit.gpgsign=false commit -qm base && echo two >> f.txt && echo new > n.txt )
  ( cd "$G" && SEND diff --patch --to smoke-recv >/dev/null 2>&1 ) && ok "send a git patch" || bad "git patch"
  P1=$(ls "$T/inbox"/*.patch 2>/dev/null | head -1)
  if [ -n "$P1" ] && ( cd "$G" && git stash -q -u 2>/dev/null; git apply --check "$P1" ); then ok "received patch applies to the base commit"; else bad "patch does not apply"; fi
else
  echo "  skip  git tests (git not installed)"
fi

# --- wrong PIN, lockout -----------------------------------------------------------
printf 'x\n' > "$T/work/small.txt"
BADPIN=$([ "$PIN" = "000000" ] && echo 111111 || echo 000000)
for n in 1 2 3; do DROP_PIN=$BADPIN DROP_HOME="$T/a" "$BIN" --to smoke-recv "$T/work/small.txt" >/dev/null 2>&1; rc=$?; done
[ "$rc" -eq 4 ] && ok "wrong PIN is rejected (exit 4) and 3 failures lock the receiver" || bad "wrong PIN exit code was $rc, want 4"
SEND --to smoke-recv "$T/work/small.txt" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 4 ] && ok "correct PIN is refused while locked" || bad "locked receiver accepted the PIN (exit $rc)"
[ ! -e "$T/inbox/small.txt" ] && ok "nothing was written by failed or locked attempts" || bad "file written despite lockout"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

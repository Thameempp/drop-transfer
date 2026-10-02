#!/bin/sh
# Builds drop and installs it somewhere that is ALREADY on your PATH, so that
# `drop` works immediately in new terminals without any manual step.
#
#   make install                      pick a writable directory on PATH automatically
#   make install BINDIR=/some/dir     choose the directory yourself
#
# Directory choice (first that exists on PATH and is writable by you):
#   ~/.local/bin, ~/bin, /opt/homebrew/bin, /usr/local/bin
# If none qualifies, ~/.local/bin is created and added to your shell startup file.
set -eu

VERSION=${VERSION:-0.1.0-dev}
LDFLAGS="-X github.com/thameem/drop/internal/cli.Version=$VERSION"

if ! command -v go >/dev/null 2>&1; then
  echo "error: Go is not installed or not on your PATH."
  echo "install Go from https://go.dev/dl/ (or: brew install go) and try again."
  exit 1
fi

on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac; }

EXE=""
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

pick_dir() {
  for d in "$HOME/.local/bin" "$HOME/bin" /opt/homebrew/bin /usr/local/bin "$HOME/go/bin"; do
    if [ -d "$d" ] && [ -w "$d" ] && on_path "$d"; then echo "$d"; return 0; fi
  done
  return 1
}

if [ -n "${BINDIR:-}" ]; then
  DIR=$BINDIR
elif DIR=$(pick_dir); then
  :
else
  DIR="$HOME/.local/bin"
fi
mkdir -p "$DIR" || { echo "cannot create $DIR (try: make install BINDIR=<a directory you can write to>)"; exit 1; }
[ -w "$DIR" ] || { echo "$DIR is not writable (try: make install BINDIR=\$HOME/.local/bin)"; exit 1; }

# Build to a temp file, then move into place, so a running drop or a failed
# build never leaves a half-written binary behind.
TMP=$(mktemp "$DIR/.drop-install.XXXXXX")
trap 'rm -f "$TMP"' EXIT
go build -ldflags "$LDFLAGS" -o "$TMP" ./cmd/drop
chmod 755 "$TMP"
mv -f "$TMP" "$DIR/drop$EXE"
trap - EXIT
echo "installed: $DIR/drop$EXE"

# If the directory is not on PATH yet, add it to the shell startup file.
if ! on_path "$DIR"; then
  case "$(basename "${SHELL:-sh}")" in
    zsh)  RC="$HOME/.zshrc" ;;
    bash) if [ -f "$HOME/.bash_profile" ] && [ "$(uname)" = Darwin ]; then RC="$HOME/.bash_profile"; else RC="$HOME/.bashrc"; fi ;;
    fish) RC="" ;;
    *)    RC="$HOME/.profile" ;;
  esac
  if [ -z "$RC" ]; then
    echo "NOTE: add $DIR to your PATH (fish: fish_add_path $DIR), then open a new terminal."
  else
    if ! grep -qs "drop: install directory" "$RC" 2>/dev/null; then
      printf '\n# drop: install directory\nexport PATH="$PATH:%s"\n' "$DIR" >> "$RC"
      echo "added $DIR to PATH in $RC"
    fi
    echo "NOTE: open a NEW terminal (or run: source $RC) before using 'drop'."
  fi
fi

# Make sure the drop that will actually run is the one we just installed.
hash -r 2>/dev/null || true
if on_path "$DIR"; then
  FOUND=$(command -v "drop$EXE" 2>/dev/null || command -v drop 2>/dev/null || true)
  if [ -n "$FOUND" ] && [ "$FOUND" != "$DIR/drop$EXE" ] && [ "$FOUND" != "$DIR/drop" ]; then
    echo "WARNING: another 'drop' comes first on your PATH and will shadow this one:"
    echo "         $FOUND"
    echo "         remove it (rm \"$FOUND\") or put $DIR earlier in PATH."
  else
    echo "check: $("$DIR/drop$EXE" --version)"
  fi
fi

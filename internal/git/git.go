// Package git reads a repository's state through the git command line. It is
// strictly read-only: it never stages, commits, checks out, or changes config,
// and it avoids even the index refresh that plain `git status` performs.
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNoGit means the git executable was not found.
var ErrNoGit = errors.New("git is not installed or not on PATH")

// ErrNotRepo means the directory is not inside a git working tree.
var ErrNotRepo = errors.New("not inside a git repository")

// runner executes git with a hardened environment. Arguments are always passed
// as a slice (never through a shell).
type runner struct {
	dir string
	// index, when set, is a private copy of the repository's index. Porcelain
	// commands such as `git diff` refresh and rewrite the index (a harmless
	// stat-cache update, but still a write to the user's repository, and
	// GIT_OPTIONAL_LOCKS does not prevent it). Pointing every command at a copy
	// makes "never modifies the repository" structural instead of per-command.
	index string
}

// hardening applied to every invocation:
//   - GIT_OPTIONAL_LOCKS=0: read commands must not take locks or rewrite the index
//   - GIT_LITERAL_PATHSPECS=1: file names are never interpreted as globs/magic
//   - GIT_TERMINAL_PROMPT=0 / GIT_PAGER=cat: never block on a prompt or pager
//   - LC_ALL=C: stable, parseable messages
//   - core.fsmonitor=false: a repository config must not launch a helper program
var hardenEnv = []string{
	"GIT_OPTIONAL_LOCKS=0", "GIT_LITERAL_PATHSPECS=1", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "LC_ALL=C",
}

func (r runner) cmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{"-c", "core.fsmonitor=false", "-c", "core.quotepath=false"}, args...)
	c := exec.CommandContext(ctx, "git", full...)
	c.Dir = r.dir
	c.Env = append(os.Environ(), hardenEnv...)
	if r.index != "" {
		c.Env = append(c.Env, "GIT_INDEX_FILE="+r.index)
	}
	return c
}

// output runs git and returns stdout. A non-zero exit becomes an error carrying
// git's own message (stderr), which is already user-readable.
func (r runner) output(ctx context.Context, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	c := r.cmd(ctx, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return nil, r.wrap(err, errb.String(), args)
	}
	return out.Bytes(), nil
}

// stream runs git writing stdout to w (patches can be large). okExit lists
// exit codes that are not failures (e.g. 1 for `diff --no-index` with changes).
func (r runner) stream(ctx context.Context, w io.Writer, okExit []int, args ...string) error {
	var errb bytes.Buffer
	c := r.cmd(ctx, args...)
	c.Stdout, c.Stderr = w, &errb
	err := c.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		for _, code := range okExit {
			if ee.ExitCode() == code {
				return nil
			}
		}
	}
	return r.wrap(err, errb.String(), args)
}

func (r runner) wrap(err error, stderr string, args []string) error {
	if errors.Is(err, exec.ErrNotFound) {
		return ErrNoGit
	}
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("git %s: %s", args[0], msg)
}

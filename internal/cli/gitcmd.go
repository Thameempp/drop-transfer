package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/git"
	"github.com/thameem/drop/internal/project"
	"github.com/thameem/drop/internal/security"
)

type gitOptions struct {
	sendOptions
	patch  bool
	files  bool
	staged bool
	all    bool // git: bundle every branch and tag
}

func newDiffCmd(verbose *bool) *cobra.Command {
	var o gitOptions
	cmd := &cobra.Command{
		Use:   "diff [dir]",
		Short: "Send your uncommitted Git changes as a patch or as the changed files",
		Long: `Shows what changed in the Git repository (staged, unstaged and new files) and
sends it to another device. drop never modifies your repository: it does not
stage, commit, or even refresh the index.

  --patch   a .patch file the receiver applies with "git apply"
  --files   only the changed files, in their folders (deleted files are listed
            but cannot be sent this way; use the patch for deletions)

Files that look like secrets are withheld unless you pass --include-secrets.`,
		Example: "  drop diff\n  drop diff --patch --to windows\n  drop diff --staged --files",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			if o.patch && o.files {
				return usageErr("choose either --patch or --files, not both")
			}
			return runDiff(cmd.Context(), *verbose, o, dir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.to, "to", "", "target device name, ID, or host:port (skips the menu)")
	f.DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to search for devices")
	f.BoolVar(&o.patch, "patch", false, "send a patch file")
	f.BoolVar(&o.files, "files", false, "send the changed files")
	f.BoolVar(&o.staged, "staged", false, "only changes recorded in the index (git add)")
	f.BoolVar(&o.dryRun, "dry-run", false, "show the changes and what would be withheld, then stop")
	f.BoolVar(&o.includeSecrets, "include-secrets", false, "also send files that look like secrets")
	return cmd
}

func newGitCmd(verbose *bool) *cobra.Command {
	var o gitOptions
	cmd := &cobra.Command{
		Use:   "git [dir]",
		Short: "Send the Git repository itself as a bundle (full history)",
		Long: `Packs the current branch with its complete history into a single .bundle file
and sends it. The receiver gets a real repository with: git clone <file>.bundle

Uncommitted work is not included (use "drop diff" for that). Anything ever
committed is in the history, including secrets that were committed once and
later removed, so drop asks before sending a repository whose history contains
files that look like secrets.`,
		Example: "  drop git\n  drop git --all --to windows",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			return runGitBundle(cmd.Context(), *verbose, o, dir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.to, "to", "", "target device name, ID, or host:port (skips the menu)")
	f.DurationVar(&o.timeout, "timeout", 3*time.Second, "how long to search for devices")
	f.BoolVar(&o.all, "all", false, "bundle every branch and tag, not just the current branch")
	f.BoolVar(&o.dryRun, "dry-run", false, "show what would be sent, then stop")
	f.BoolVar(&o.includeSecrets, "include-secrets", false, "send even if the repository tracks files that look like secrets")
	return cmd
}

// withheld is a change kept out of the transfer because it looks sensitive.
type withheld struct {
	Path, Reason string
}

// screenChanges splits changes into those safe to send and those withheld as
// likely secrets (by name, and by content for files that still exist).
func screenChanges(root string, changes []git.Change, includeSecrets bool) (keep []git.Change, held []withheld) {
	for _, c := range changes {
		if !includeSecrets {
			if why, ok := sensitiveChange(root, c); ok {
				held = append(held, withheld{c.Path, why})
				continue
			}
		}
		keep = append(keep, c)
	}
	return
}

func sensitiveChange(root string, c git.Change) (string, bool) {
	for _, p := range []string{c.Path, c.OldPath} {
		if p == "" {
			continue
		}
		// Every directory component counts too (.ssh/config, .aws/credentials).
		for _, part := range strings.Split(p, "/") {
			if _, ok := project.SensitiveName(part); ok {
				why, _ := project.SensitiveName(part)
				return why, true
			}
			if part == ".ssh" || part == ".aws" || part == ".gnupg" || part == ".kube" {
				return "credentials folder", true
			}
		}
	}
	if c.Kind != git.Deleted {
		abs := filepath.Join(root, filepath.FromSlash(c.Path))
		if st, err := os.Lstat(abs); err == nil && st.Mode().IsRegular() {
			if kind, ok := project.ScanContent(abs, st.Size()); ok {
				return "matches a known credential format: " + kind, true
			}
		}
	}
	return "", false
}

func runDiff(ctx context.Context, verbose bool, o gitOptions, dir string) error {
	repo, err := git.Open(ctx, dir)
	if err != nil {
		return gitError(err)
	}
	defer repo.Close()
	changes, err := repo.Changes(ctx, o.staged)
	if err != nil {
		return gitError(err)
	}
	scope := "Git changes"
	if o.staged {
		scope = "Staged changes"
	}
	if len(changes) == 0 {
		fmt.Fprintf(os.Stderr, "%s: %s — nothing to send.\n", scope, repoLabel(repo))
		return nil
	}
	keep, held := screenChanges(repo.Root, changes, o.includeSecrets)
	printChanges(os.Stderr, scope, repo, keep, held, o.includeSecrets)
	if len(keep) == 0 {
		return usageErr("every change was withheld as a possible secret; use --include-secrets to send them anyway")
	}
	if o.dryRun {
		fmt.Fprintln(os.Stderr, "Dry run: nothing was sent.")
		return nil
	}

	mode, err := chooseDiffMode(o, keep)
	if err != nil {
		return err
	}
	a, err := loadApp(verbose)
	if err != nil {
		return err
	}

	switch mode {
	case "patch":
		tmp, err := os.MkdirTemp("", "drop-patch-")
		if err != nil {
			return fmt.Errorf("create temporary folder: %w", err)
		}
		defer os.RemoveAll(tmp)
		name := safeFileName(repo.Name+"-"+repo.Branch) + ".patch"
		file := filepath.Join(tmp, name)
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		bw := bufio.NewWriter(f)
		werr := repo.WritePatch(ctx, bw, keep, o.staged)
		if ferr := bw.Flush(); werr == nil {
			werr = ferr
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return gitError(werr)
		}
		if st, err := os.Stat(file); err != nil || st.Size() == 0 {
			return usageErr("the patch is empty (only non-text or unsupported changes?)")
		}
		fmt.Fprintf(os.Stderr, "Patch %s: %s\n", name, humanBytes(fileSize(file)))
		err = a.deliver(ctx, o.sendOptions, job{ttype: security.TransferGit, path: file, what: name})
		if err == nil {
			fmt.Printf("On the receiving device, inside the repository: git apply %s\n", shellQuote(name))
		}
		return err

	default: // files
		var sendable []string
		var deleted []string
		for _, c := range keep {
			if c.Kind == git.Deleted {
				deleted = append(deleted, c.Path)
				continue
			}
			sendable = append(sendable, c.Path)
		}
		if len(deleted) > 0 {
			fmt.Fprintf(os.Stderr, "Deleted files cannot be sent as files (%s). Use --patch to include deletions.\n", plural(len(deleted), "file", "files"))
		}
		if len(sendable) == 0 {
			return usageErr("no existing files to send; use --patch for deletions")
		}
		scan, err := filesystem.NewScanFromPaths(repo.Root, repo.Name+"-changes", sendable)
		if err != nil {
			return withCode(ExitUsage, err)
		}
		for _, sk := range scan.Skipped {
			fmt.Fprintf(os.Stderr, "Not sent: %s (%s)\n", sanitizeLabel(sk.Path), sk.Reason)
		}
		return a.deliver(ctx, o.sendOptions, job{ttype: security.TransferGit, scan: scan, what: scan.Name + "/"})
	}
}

func chooseDiffMode(o gitOptions, keep []git.Change) (string, error) {
	switch {
	case o.patch:
		return "patch", nil
	case o.files:
		return "files", nil
	}
	if !(hasTTY() && isTTY(os.Stderr)) {
		return "", usageErr("choose what to send with --patch or --files (no terminal for a menu)")
	}
	i, err := pickOne("Send", []string{"Send patch", "Send changed files"})
	if err != nil {
		return "", err
	}
	return []string{"patch", "files"}[i], nil
}

func runGitBundle(ctx context.Context, verbose bool, o gitOptions, dir string) error {
	repo, err := git.Open(ctx, dir)
	if err != nil {
		return gitError(err)
	}
	defer repo.Close()
	if !repo.HasCommits {
		return usageErr("the repository has no commits yet; there is nothing to bundle")
	}
	scope := "current branch " + repo.Branch
	if o.all {
		scope = "all branches and tags"
	}
	fmt.Fprintf(os.Stderr, "Git repository: %s — %s, %s\n", repo.Name, scope, plural(repo.CommitCount(ctx), "commit", "commits"))
	fmt.Fprintln(os.Stderr, "Uncommitted changes are not included (see `drop diff`).")

	tracked, err := repo.HistoryFiles(ctx, o.all)
	if err != nil {
		return gitError(err)
	}
	var risky []string
	for _, f := range tracked {
		for _, part := range strings.Split(f, "/") {
			if _, ok := project.SensitiveName(part); ok {
				risky = append(risky, f)
				break
			}
		}
	}
	if len(risky) > 0 && !o.includeSecrets {
		fmt.Fprintf(os.Stderr, "\n⚠ The history being sent contains %d file(s) that look like secrets, even if they were deleted later:\n", len(risky))
		for i, f := range risky {
			if i == 8 {
				fmt.Fprintf(os.Stderr, "    … and %d more\n", len(risky)-8)
				break
			}
			fmt.Fprintf(os.Stderr, "    %s\n", sanitizeLabel(f))
		}
		fmt.Fprintln(os.Stderr, "  Deleting a file in a later commit does not remove it from history.")
		if o.dryRun {
			fmt.Fprintln(os.Stderr, "\nDry run: nothing was sent.")
			return nil
		}
		if !confirm("Send the repository anyway? [y/N] ") {
			return usageErr("not sent. Remove the files from history, or pass --include-secrets to send anyway")
		}
	}
	if o.dryRun {
		fmt.Fprintln(os.Stderr, "\nDry run: nothing was sent.")
		return nil
	}

	tmp, err := os.MkdirTemp("", "drop-bundle-")
	if err != nil {
		return fmt.Errorf("create temporary folder: %w", err)
	}
	defer os.RemoveAll(tmp)
	name := safeFileName(repo.Name) + ".bundle"
	file := filepath.Join(tmp, name)
	if err := repo.Bundle(ctx, file, o.all); err != nil {
		return gitError(err)
	}
	fmt.Fprintf(os.Stderr, "Bundle %s: %s\n", name, humanBytes(fileSize(file)))
	a, err := loadApp(verbose)
	if err != nil {
		return err
	}
	err = a.deliver(ctx, o.sendOptions, job{ttype: security.TransferGit, path: file, what: name})
	if err == nil {
		fmt.Printf("On the receiving device: git clone %s\n", shellQuote(name))
	}
	return err
}

func printChanges(w *os.File, scope string, repo *git.Repo, keep []git.Change, held []withheld, included bool) {
	fmt.Fprintf(w, "%s: %s\n", scope, repoLabel(repo))
	groups := []struct {
		title string
		kind  git.Kind
	}{{"Modified", git.Modified}, {"Added", git.Added}, {"Deleted", git.Deleted}, {"Renamed", git.Renamed}}
	for _, g := range groups {
		var lines []string
		for _, c := range keep {
			if c.Kind != g.kind {
				continue
			}
			l := sanitizeLabel(c.Path)
			if c.Kind == git.Renamed && c.OldPath != "" {
				l = sanitizeLabel(c.OldPath) + " → " + l
			}
			if c.Untracked {
				l += "  (untracked)"
			}
			lines = append(lines, l)
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s:\n", g.title)
		for i, l := range lines {
			if i == 25 {
				fmt.Fprintf(w, "    … and %d more\n", len(lines)-25)
				break
			}
			fmt.Fprintf(w, "    %s\n", l)
		}
	}
	if len(held) > 0 {
		fmt.Fprintf(w, "\n⚠ Withheld because they look sensitive:\n")
		for i, h := range held {
			if i == 10 {
				fmt.Fprintf(w, "    … and %d more\n", len(held)-10)
				break
			}
			fmt.Fprintf(w, "    %s  (%s)\n", sanitizeLabel(h.Path), h.Reason)
		}
		fmt.Fprintln(w, "  Detection is a safety net, not a guarantee. Use --include-secrets to send them.")
	}
	if included {
		fmt.Fprintln(w, "\n⚠ --include-secrets: files that look like secrets are NOT being withheld.")
	}
	fmt.Fprintln(w)
}

func repoLabel(r *git.Repo) string {
	return fmt.Sprintf("%s (%s)", sanitizeLabel(r.Name), sanitizeLabel(r.Branch))
}

func gitError(err error) error {
	switch {
	case errors.Is(err, git.ErrNoGit):
		return withCode(ExitUsage, fmt.Errorf("%w; install Git to use this command", err))
	case errors.Is(err, git.ErrNotRepo):
		return withCode(ExitUsage, errors.New("this folder is not inside a Git repository"))
	case errors.Is(err, git.ErrConflicts):
		return withCode(ExitUsage, err)
	}
	return err
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// safeFileName makes a name that is valid on every OS (branch names contain '/').
func safeFileName(s string) string {
	s = strings.Trim(unsafeFileChars.ReplaceAllString(s, "-"), "-.")
	if s == "" {
		s = "drop"
	}
	return path.Clean(s)
}

func shellQuote(s string) string {
	if !regexp.MustCompile(`[^A-Za-z0-9._/-]`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// confirm asks a yes/no question on the terminal; the default is no.
func confirm(prompt string) bool {
	f, err := openTTY()
	if err != nil {
		return false
	}
	defer f.Close()
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(f).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}

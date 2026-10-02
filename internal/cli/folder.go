package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/project"
)

// scanFolder inspects a directory, applies the project-aware rules and tells
// the user exactly what will and will not be sent. Nothing is left out invisibly.
func scanFolder(path string, o sendOptions) (*filesystem.ScanResult, error) {
	if isTTY(os.Stderr) {
		fmt.Fprint(os.Stderr, "Preparing…\r")
	}
	info, isProject := project.Detect(path)
	isProject = isProject && !o.all
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, withCode(ExitUsage, err)
	}
	scan, err := filesystem.ScanWith(path, filesystem.ScanOptions{
		Rules: project.NewRules(abs, project.Options{Project: isProject, IncludeSecrets: o.includeSecrets}),
	})
	if isTTY(os.Stderr) {
		fmt.Fprint(os.Stderr, "\033[K")
	}
	if err != nil {
		return nil, withCode(ExitUsage, err)
	}
	printPlan(os.Stderr, scan, info, isProject, o)
	return scan, nil
}

func printPlan(w *os.File, scan *filesystem.ScanResult, info *project.Info, isProject bool, o sendOptions) {
	if isProject {
		kinds := ""
		if len(info.Kinds) > 0 {
			kinds = " (" + strings.Join(info.Kinds, ", ") + ")"
		}
		fmt.Fprintf(w, "Project detected: %s%s\n", sanitizeLabel(scan.Name), kinds)
	} else {
		fmt.Fprintf(w, "Folder: %s\n", sanitizeLabel(scan.Name))
	}
	fmt.Fprintf(w, "\n  Transferable: %s (%s, %s)\n", humanBytes(scan.TotalSize),
		plural(scan.Files, "file", "files"), plural(scan.Dirs, "folder", "folders"))

	var secrets, others []filesystem.Excluded
	for _, e := range scan.Excluded {
		if e.Category == filesystem.CatSensitive {
			secrets = append(secrets, e)
		} else {
			others = append(others, e)
		}
	}
	if size, files := scan.ExcludedTotal(); len(scan.Excluded) > 0 {
		fmt.Fprintf(w, "  Excluded:     %s (%s)\n", humanBytes(size), plural(files, "file", "files"))
	}
	limit := 8
	if o.explain {
		limit = len(others)
	}
	for i, e := range others {
		if i == limit {
			fmt.Fprintf(w, "    … and %d more (use --explain to list everything)\n", len(others)-limit)
			break
		}
		name := sanitizeLabel(e.Path)
		if e.Dir {
			name += "/"
		}
		fmt.Fprintf(w, "    %-28s %9s  %s\n", shorten(name, 28), humanBytes(e.Size), e.Detail)
	}

	if len(secrets) > 0 {
		fmt.Fprintf(w, "\n⚠ Potential sensitive files detected and excluded:\n")
		limit := 10
		if o.explain {
			limit = len(secrets)
		}
		for i, e := range secrets {
			if i == limit {
				fmt.Fprintf(w, "    … and %d more (use --explain)\n", len(secrets)-limit)
				break
			}
			name := sanitizeLabel(e.Path)
			if e.Dir {
				name += "/"
			}
			fmt.Fprintf(w, "    %s  (%s)\n", name, e.Detail)
		}
		fmt.Fprintln(w, "  Detection is a safety net, not a guarantee: other secrets may still be sent.")
		fmt.Fprintln(w, "  Use --include-secrets to send these files anyway.")
	}
	if o.includeSecrets {
		fmt.Fprintln(w, "\n⚠ --include-secrets: files that look like secrets are NOT being excluded.")
	}
	if n := len(scan.Skipped); n > 0 {
		fmt.Fprintf(w, "\nNot sent (%d): symbolic links and special files are never followed or copied:\n", n)
		for i, sk := range scan.Skipped {
			if i == 5 {
				fmt.Fprintf(w, "  … and %d more\n", n-5)
				break
			}
			fmt.Fprintf(w, "  %s (%s)\n", sanitizeLabel(sk.Path), sk.Reason)
		}
	}
	if scan.Files+scan.Dirs == 0 {
		fmt.Fprintln(w, "\nNothing to send: every file was excluded or the folder is empty.")
	}
	fmt.Fprintln(w)
}

package project

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/thameem/drop/internal/filesystem"
)

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetect(t *testing.T) {
	mk := func(files ...string) string {
		d := filepath.Join(t.TempDir(), "proj")
		os.MkdirAll(d, 0o755)
		for _, f := range files {
			if strings.HasSuffix(f, "/") {
				os.MkdirAll(filepath.Join(d, f), 0o755)
			} else {
				os.WriteFile(filepath.Join(d, f), nil, 0o644)
			}
		}
		return d
	}
	if info, ok := Detect(mk("go.mod", "package.json", ".git/", "README.md")); !ok ||
		strings.Join(info.Kinds, ",") != "Git,Go,Node.js" || info.Name != "proj" {
		t.Fatalf("%+v %v", info, ok)
	}
	if _, ok := Detect(mk("README.md", "photo1.jpg", "notes.txt")); ok {
		t.Fatal("a folder with only a README was treated as a project")
	}
	if _, ok := Detect(mk()); ok {
		t.Fatal("empty folder detected as a project")
	}
	if _, ok := Detect(mk("Makefile")); !ok {
		t.Fatal("Makefile project not detected")
	}
	// Only the directory itself counts, never its parents.
	parent := mk("go.mod")
	child := filepath.Join(parent, "docs")
	os.MkdirAll(child, 0o755)
	if _, ok := Detect(child); ok {
		t.Fatal("subdirectory inherited its parent's project status")
	}
}

func TestSensitiveName(t *testing.T) {
	for _, n := range []string{".env", ".env.local", ".env.production", "server.pem", "tls.key", "id_rsa", "id_ed25519",
		"credentials.json", "service-account-prod.json", "client_secret_123.json", ".netrc", ".git-credentials",
		"keystore.jks", "cert.p12", "secrets.yaml", "terraform.tfstate", "ID_RSA", ".ENV"} {
		if _, ok := SensitiveName(n); !ok {
			t.Errorf("%q should be sensitive", n)
		}
	}
	for _, n := range []string{".env.example", ".env.sample", ".env.template", "environment.py", "main.go", "key.go",
		"keyboard.txt", "id_rsa.pub", "monkey.txt", "README.md", "env.example", "package.json"} {
		if why, ok := SensitiveName(n); ok {
			t.Errorf("%q wrongly flagged (%s)", n, why)
		}
	}
}

func TestScanContent(t *testing.T) {
	dir := t.TempDir()
	check := func(name, content string) (string, bool) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o644)
		return ScanContent(p, int64(len(content)))
	}
	for name, content := range map[string]string{
		"a.py":   `aws_key = "AKIAIOSFODNN7ABCDEFG"`,
		"b.txt":  "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
		"c.js":   `const t = "ghp_` + strings.Repeat("a", 36) + `"`,
		"d.yml":  "token: xoxb-123456789012-abcdefghij",
		"e.go":   `k := "sk_live_` + strings.Repeat("Z", 24) + `"`,
		"f.json": `{"k":"AIza` + strings.Repeat("x", 35) + `"}`,
		"g.txt":  "key=sk-ant-" + strings.Repeat("a", 30),
	} {
		if _, ok := check(name, content); !ok {
			t.Errorf("%s: secret not detected", name)
		}
	}
	for name, content := range map[string]string{
		"ok1.py":  "def add(a, b): return a + b",
		"ok2.md":  "Example key from the AWS docs: AKIAIOSFODNN7EXAMPLE",
		"ok3.txt": "ghp_tooshort",
		"ok4.go":  "password := os.Getenv(\"PASSWORD\")",
	} {
		if k, ok := check(name, content); ok {
			t.Errorf("%s: false positive (%s)", name, k)
		}
	}
	// The matched secret itself must never be returned.
	if k, _ := check("h.py", `AKIAIOSFODNN7ABCDEFG`); strings.Contains(k, "AKIA") {
		t.Fatal("finding leaks the secret")
	}
	// Binary and oversized files are not scanned.
	bin := append([]byte{0, 1, 2}, []byte("AKIAIOSFODNN7ABCDEFG")...)
	p := filepath.Join(dir, "x.dat")
	os.WriteFile(p, bin, 0o644)
	if _, ok := ScanContent(p, int64(len(bin))); ok {
		t.Fatal("binary file scanned")
	}
	if _, ok := ScanContent(p, maxScanBytes+1); ok {
		t.Fatal("oversized file scanned")
	}
}

func scanProject(t *testing.T, root string, o Options) *filesystem.ScanResult {
	t.Helper()
	res, err := filesystem.ScanWith(root, filesystem.ScanOptions{Rules: NewRules(root, o)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func included(res *filesystem.ScanResult) []string {
	var out []string
	for _, e := range res.Entries {
		if !e.Dir {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

func excludedMap(res *filesystem.ScanResult) map[string]filesystem.Excluded {
	m := map[string]filesystem.Excluded{}
	for _, e := range res.Excluded {
		m[e.Path] = e
	}
	return m
}

func makeProject(t *testing.T) string {
	root := filepath.Join(t.TempDir(), "pdf-assistant")
	put(t, root, "go.mod", "module x")
	put(t, root, "main.py", "print(1)")
	put(t, root, "src/app.py", "x=1")
	put(t, root, "node_modules/lib/index.js", strings.Repeat("x", 5000))
	put(t, root, "node_modules/lib/deep/more.js", strings.Repeat("y", 3000))
	put(t, root, "src/__pycache__/app.cpython-311.pyc", "bytecode")
	put(t, root, ".git/HEAD", "ref: refs/heads/main")
	put(t, root, ".git/objects/aa/bb", strings.Repeat("g", 2000))
	put(t, root, ".env", "API_KEY=abc123")
	put(t, root, ".env.example", "API_KEY=")
	put(t, root, "config/credentials.json", "{}")
	put(t, root, "tests/fixture.txt", `AWS_KEY=AKIAIOSFODNN7ABCDEFG`)
	put(t, root, "dist/bundle.js", "built")
	put(t, root, "logs/app.log", "log")
	put(t, root, ".gitignore", "*.log\n.env\n")
	put(t, root, ".DS_Store", "x")
	put(t, root, "venv/pyvenv.cfg", "home = /usr/bin")
	put(t, root, "venv/lib/x.py", "z")
	put(t, root, "README.md", "# hi")
	return root
}

func TestProjectScanExcludesWhatItShould(t *testing.T) {
	root := makeProject(t)
	res := scanProject(t, root, Options{Project: true})
	got := included(res)
	want := []string{".env.example", ".gitignore", "README.md", "go.mod", "main.py", "src/app.py"}
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("included:\n  got  %v\n  want %v", got, want)
	}
	ex := excludedMap(res)
	for path, cat := range map[string]filesystem.Category{
		"node_modules": filesystem.CatGenerated, ".git": filesystem.CatVCS, ".env": filesystem.CatSensitive,
		"config/credentials.json": filesystem.CatSensitive, "tests/fixture.txt": filesystem.CatSensitive,
		"dist": filesystem.CatGenerated, "logs/app.log": filesystem.CatGitignore, "venv": filesystem.CatGenerated,
		"src/__pycache__": filesystem.CatGenerated, ".DS_Store": filesystem.CatGenerated,
	} {
		e, ok := ex[path]
		if !ok || e.Category != cat {
			t.Errorf("%s: %+v (present=%v), want category %q", path, e, ok, cat)
		}
	}
	if ex["node_modules"].Size != 8000 || ex["node_modules"].Files != 2 {
		t.Errorf("excluded directory not measured: %+v", ex["node_modules"])
	}
	if !strings.Contains(ex["tests/fixture.txt"].Detail, "AWS") {
		t.Errorf("reason: %q", ex["tests/fixture.txt"].Detail)
	}
	for _, e := range res.Excluded { // reasons must never include the secret itself
		if strings.Contains(e.Detail, "AKIA") || strings.Contains(e.Detail, "abc123") {
			t.Fatalf("exclusion detail leaks a secret: %q", e.Detail)
		}
	}
	for i := 1; i < len(res.Excluded); i++ {
		if res.Excluded[i].Size > res.Excluded[i-1].Size {
			t.Fatal("exclusions not sorted largest first")
		}
	}
}

func TestIncludeSecretsOverride(t *testing.T) {
	root := makeProject(t)
	res := scanProject(t, root, Options{Project: true, IncludeSecrets: true})
	got := strings.Join(included(res), "|")
	for _, f := range []string{".env", "config/credentials.json", "tests/fixture.txt"} {
		// .env is still excluded: it is listed in .gitignore, a separate, ordinary rule.
		if f == ".env" {
			if strings.Contains(got, "|.env|") || strings.HasPrefix(got, ".env|") {
				t.Errorf(".gitignore'd .env was sent")
			}
			continue
		}
		if !strings.Contains(got, f) {
			t.Errorf("%s not included with IncludeSecrets", f)
		}
	}
}

func TestNonProjectOnlyProtectsSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "holiday-photos")
	put(t, root, "a.jpg", "x")
	put(t, root, "node_modules/x.js", "this folder is not a project, so keep it")
	put(t, root, "build/out.txt", "keep")
	put(t, root, ".env", "SECRET=1")
	put(t, root, ".gitignore", "*.jpg\n")
	res := scanProject(t, root, Options{Project: false})
	got := strings.Join(included(res), "|")
	if !strings.Contains(got, "a.jpg") || !strings.Contains(got, "node_modules/x.js") || !strings.Contains(got, "build/out.txt") {
		t.Fatalf("non-project folder was filtered like a project: %s", got)
	}
	if strings.Contains(got, ".env") && !strings.Contains(got, ".gitignore") {
		t.Fatal(".env sent")
	}
	if _, ok := excludedMap(res)[".env"]; !ok {
		t.Fatal("secret in a plain folder was not excluded")
	}
}

func TestAllModeKeepsEverythingExceptSecrets(t *testing.T) {
	root := makeProject(t)
	res := scanProject(t, root, Options{Project: false})
	got := strings.Join(included(res), "|")
	for _, f := range []string{"node_modules/lib/index.js", ".git/HEAD", "dist/bundle.js", "logs/app.log"} {
		if !strings.Contains(got, f) {
			t.Errorf("%s missing in --all mode", f)
		}
	}
	if strings.Contains(got, ".env|") || strings.HasSuffix(got, ".env") {
		t.Fatal("secrets sent in --all mode")
	}
}

func TestTargetOnlyGeneratedForRealBuildSystems(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "p1")
	put(t, plain, "package.json", "{}")
	put(t, plain, "target/important.txt", "real source")
	if got := strings.Join(included(scanProject(t, plain, Options{Project: true})), "|"); !strings.Contains(got, "target/important.txt") {
		t.Fatal("target/ excluded in a non-Rust/Java project")
	}
	rust := filepath.Join(t.TempDir(), "p2")
	put(t, rust, "Cargo.toml", "")
	put(t, rust, "target/debug/x", "obj")
	if _, ok := excludedMap(scanProject(t, rust, Options{Project: true}))["target"]; !ok {
		t.Fatal("Rust target/ not excluded")
	}
	// A directory just *named* venv is only excluded if it is a virtualenv.
	v := filepath.Join(t.TempDir(), "p3")
	put(t, v, "go.mod", "")
	put(t, v, "venv/notes.txt", "my own folder")
	if got := strings.Join(included(scanProject(t, v, Options{Project: true})), "|"); !strings.Contains(got, "venv/notes.txt") {
		t.Fatal("non-virtualenv folder named venv was excluded")
	}
}

func TestNestedGitignoreAndNegation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "p")
	put(t, root, "go.mod", "")
	put(t, root, ".gitignore", "*.gen\n!keep.gen\n")
	put(t, root, "a.gen", "x")
	put(t, root, "keep.gen", "x")
	put(t, root, "pkg/.gitignore", "local.txt\n!a.gen\n")
	put(t, root, "pkg/local.txt", "x")
	put(t, root, "pkg/a.gen", "x")       // re-included by the deeper file
	put(t, root, "other/local.txt", "x") // the pkg rule must not leak here
	got := strings.Join(included(scanProject(t, root, Options{Project: true})), "|")
	for _, f := range []string{"keep.gen", "pkg/a.gen", "other/local.txt"} {
		if !strings.Contains(got, f) {
			t.Errorf("%s should be included: %s", f, got)
		}
	}
	for _, f := range []string{"|a.gen", "pkg/local.txt"} {
		if strings.Contains("|"+got, f) {
			t.Errorf("%s should be excluded", f)
		}
	}
}

func TestGitInfoExcludeHonoured(t *testing.T) {
	root := filepath.Join(t.TempDir(), "p")
	put(t, root, "go.mod", "")
	put(t, root, ".git/info/exclude", "scratch.txt\n")
	put(t, root, "scratch.txt", "x")
	put(t, root, "real.txt", "x")
	got := included(scanProject(t, root, Options{Project: true}))
	if strings.Contains(strings.Join(got, "|"), "scratch.txt") || !strings.Contains(strings.Join(got, "|"), "real.txt") {
		t.Fatalf("%v", got)
	}
}

// TestGitignoreParityWithRealGit compares our matcher with `git` itself on a
// tree exercising anchoring, **, negation, directory-only and nested files.
func TestGitignoreParityWithRealGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("path handling differs")
	}
	root := filepath.Join(t.TempDir(), "repo")
	os.MkdirAll(root, 0o755)
	put(t, root, ".gitignore", strings.Join([]string{
		"# comment", "*.log", "!important.log", "/rootonly.txt", "build/", "docs/**/draft.md", "**/cache", "tmp/*",
		"!tmp/keep.txt", "*.py[cod]", "secret?.txt", "a/b/c", "[Tt]humbs.db", "out", `\#hash.txt`, "*.o", "!lib/*.o",
	}, "\n")+"\n")
	put(t, root, "pkg/.gitignore", "*.gen\n/only-pkg.txt\nsub/\n!keep.gen\n")
	for _, f := range []string{
		"a.log", "important.log", "x/y.log", "rootonly.txt", "x/rootonly.txt", "build/o.txt", "src/build/o.txt", "build.txt",
		"docs/draft.md", "docs/a/b/draft.md", "docs/a/other.md", "cache/x", "deep/cache/y", "tmp/a.txt", "tmp/keep.txt",
		"tmp/sub/z.txt", "m.pyc", "m.pyo", "m.py", "secret1.txt", "secret12.txt", "a/b/c", "a/b/d", "Thumbs.db", "thumbs.db",
		"out/file", "src/out", "#hash.txt", "x.o", "lib/y.o", "pkg/a.gen", "pkg/keep.gen", "pkg/only-pkg.txt",
		"pkg/x/only-pkg.txt", "pkg/sub/f.txt", "pkg/inner/sub/g.txt", "main.go",
	} {
		put(t, root, f, "x")
	}
	run := func(args ...string) string {
		c := exec.Command("git", args...)
		c.Dir = root
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("init", "-q")
	var want []string
	for _, l := range strings.Split(strings.TrimSpace(run("ls-files", "--others", "--exclude-standard")), "\n") {
		if l != "" {
			want = append(want, l)
		}
	}
	sort.Strings(want)

	res, err := filesystem.ScanWith(root, filesystem.ScanOptions{Rules: NewRules(root, Options{Project: true, IncludeSecrets: true})})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range included(res) {
		if !strings.HasPrefix(e, ".git/") {
			got = append(got, e)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		missing, extra := diff(want, got), diff(got, want)
		t.Fatalf("differs from git\n  we exclude but git keeps: %v\n  we keep but git ignores:  %v", missing, extra)
	}
}

func diff(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

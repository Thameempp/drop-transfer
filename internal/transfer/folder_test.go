package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/project"
	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
)

func mkTree(t *testing.T) (root string, files map[string][]byte) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "pdf-assistant")
	big := make([]byte, 5<<20+7)
	rand.Read(big)
	files = map[string][]byte{
		"main.py":                    []byte("print('hi')\n"),
		"src/parser.py":              bytes.Repeat([]byte("x"), 1000),
		"src/utils/helpers.py":       []byte("def f(): pass\n"),
		"my docs/résumé 日本語 (1).txt": []byte("unicode and spaces"),
		"empty.txt":                  {},
		"data/model.bin":             big,
	}
	for rel, data := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(root, "empty-dir", "nested-empty"), 0o755)
	os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\n"), 0o755)
	files["run.sh"] = []byte("#!/bin/sh\n")
	return root, files
}

func (h *harness) sendFolder(root, pin string) (*SendResult, error) {
	h.t.Helper()
	scan, err := filesystem.Scan(root)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	o := h.opts(pin)
	o.Policy = h.r.Policy
	return SendFolder(ctx, h.dial(), h.selfS(), scan, o)
}

func TestFolderRoundTrip(t *testing.T) {
	root, files := mkTree(t)
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	var lastDone, lastTotal int64
	var fileEvents []string
	h.r.OnProgress = func(_ Incoming, d, tot int64) { lastDone, lastTotal = d, tot }
	h.r.OnFile = func(_ Incoming, i, n int, p string) { fileEvents = append(fileEvents, p) }

	res, err := h.sendFolder(root, testPIN)
	if err != nil {
		t.Fatal(err)
	}
	r := h.wait()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if res.Files != len(files) || r.rec.In.Files != len(files) || r.rec.In.Type != security.TransferFolder || !r.rec.In.Authorized {
		t.Fatalf("send %+v recv %+v", res, r.rec.In)
	}
	if res.SHA256 != r.rec.SHA256 {
		t.Fatal("tree hashes differ")
	}
	if filepath.Base(r.rec.Path) != "pdf-assistant" {
		t.Fatalf("saved as %s", r.rec.Path)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(r.rec.Path, filepath.FromSlash(rel)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: err=%v match=%v", rel, err, bytes.Equal(got, want))
		}
	}
	for _, dir := range []string{"empty-dir/nested-empty", "src/utils"} {
		if st, err := os.Stat(filepath.Join(r.rec.Path, filepath.FromSlash(dir))); err != nil || !st.IsDir() {
			t.Errorf("directory %s missing", dir)
		}
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(r.rec.Path, "run.sh")); st.Mode()&0o111 == 0 {
			t.Error("executable bit lost")
		}
		if st, _ := os.Stat(filepath.Join(r.rec.Path, "main.py")); st.Mode()&0o111 != 0 {
			t.Error("non-executable file became executable")
		}
	}
	if lastDone != lastTotal || lastTotal == 0 || len(fileEvents) != len(files) {
		t.Errorf("progress %d/%d, file events %d", lastDone, lastTotal, len(fileEvents))
	}
	ents, _ := os.ReadDir(h.dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers in destination: %v", ents)
	}
}

func TestEmptyFolderTransfers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nothing")
	os.MkdirAll(root, 0o755)
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	if _, err := h.sendFolder(root, testPIN); err != nil {
		t.Fatal(err)
	}
	r := h.wait()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if st, err := os.Stat(r.rec.Path); err != nil || !st.IsDir() {
		t.Fatal("empty folder not created")
	}
}

func TestExistingFolderIsNeverMergedOrReplaced(t *testing.T) {
	root, _ := mkTree(t)
	for _, c := range []Conflict{ConflictRename, ConflictReplace} { // Replace must not delete folders either
		h := newHarness(t, acceptAll(c), security.Policy{})
		existing := filepath.Join(h.dir, "pdf-assistant")
		os.MkdirAll(existing, 0o755)
		os.WriteFile(filepath.Join(existing, "precious.txt"), []byte("mine"), 0o644)
		if _, err := h.sendFolder(root, testPIN); err != nil {
			t.Fatal(err)
		}
		r := h.wait()
		if r.err != nil {
			t.Fatal(r.err)
		}
		if b, _ := os.ReadFile(filepath.Join(existing, "precious.txt")); string(b) != "mine" {
			t.Fatal("existing folder modified")
		}
		if _, err := os.Stat(filepath.Join(existing, "main.py")); err == nil {
			t.Fatal("received files merged into the existing folder")
		}
		if filepath.Base(r.rec.Path) != "pdf-assistant (1)" {
			t.Fatalf("saved as %s", r.rec.Path)
		}
	}
}

func TestFolderWithoutAuthorizationRefused(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.dial()
	rawHello(t, conn, h.snd)
	blob := []byte(`{"entries":[{"p":"x","s":1}]}`)
	sum := sha256.Sum256(blob)
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeFolder, Name: "x", Size: 1, Files: 1, SHA256: hexOf(sum[:])})
	resp, err := protocol.Expect[*protocol.TransferResponse](conn)
	if err != nil || resp.Accept {
		t.Fatalf("unauthorized folder accepted: %+v %v", resp, err)
	}
	if r := h.wait(); !errors.Is(r.err, ErrUnauthorized) {
		t.Fatalf("%v", r.err)
	}
	assertEmpty(t, h.dir)
}

func TestFolderWrongPINWritesNothing(t *testing.T) {
	root, _ := mkTree(t)
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	if _, err := h.sendFolder(root, "000000"); !errors.Is(err, security.ErrWrongPIN) {
		t.Fatalf("%v", err)
	}
	h.wait()
	assertEmpty(t, h.dir)
}

func hexOf(b []byte) string { return strings.ToLower(strings.TrimSpace(fmtSprintf("%x", b))) }

// hostileFolder starts an authorized raw session and sends the given manifest
// blob with a request whose summary matches (unless overridden).
func hostileFolder(t *testing.T, h *harness, blob []byte, mut func(*protocol.TransferRequest)) (ack *protocol.ManifestAck) {
	t.Helper()
	conn := h.authedRaw()
	sum := sha256.Sum256(blob)
	_, plan, _ := ParseManifest(blob) // may be nil for invalid manifests
	req := &protocol.TransferRequest{Mode: protocol.ModeFolder, Name: "evil", SHA256: hexOf(sum[:])}
	if plan != nil {
		req.Size, req.Files, req.Dirs = plan.Total, plan.Files, plan.Dirs
	}
	if mut != nil {
		mut(req)
	}
	protocol.WriteMsg(conn, req)
	resp, err := protocol.Expect[*protocol.TransferResponse](conn)
	if err != nil || !resp.Accept {
		t.Fatalf("response: %+v %v", resp, err)
	}
	protocol.WriteBlob(conn, blob)
	ack, err = protocol.Expect[*protocol.ManifestAck](conn)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	return ack
}

func TestHostileManifestsRejectedBeforeAnythingIsWritten(t *testing.T) {
	cases := map[string]string{
		"traversal":      `{"entries":[{"p":"../../evil","s":1}]}`,
		"absolute":       `{"entries":[{"p":"/etc/cron.d/evil","s":1}]}`,
		"backslash":      `{"entries":[{"p":"a\\..\\..\\evil","s":1}]}`,
		"missing parent": `{"entries":[{"p":"a/b","s":1}]}`,
		"duplicate":      `{"entries":[{"p":"a","s":1},{"p":"a","s":1}]}`,
		"case collision": `{"entries":[{"p":"A","s":1},{"p":"a","s":1}]}`,
		"unknown field":  `{"entries":[{"p":"a","s":1,"mode":4095}]}`,
		"negative size":  `{"entries":[{"p":"a","s":-5}]}`,
		"not json":       `garbage`,
	}
	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
			ack := hostileFolder(t, h, []byte(manifest), nil)
			if ack.OK || ack.Error == "" {
				t.Fatalf("accepted: %+v", ack)
			}
			if r := h.wait(); !errors.Is(r.err, errManifest) {
				t.Fatalf("receiver err = %v", r.err)
			}
			assertEmpty(t, h.dir)
			parent := filepath.Dir(h.dir)
			filepath.WalkDir(parent, func(p string, de fs.DirEntry, err error) error {
				if err == nil && strings.Contains(p, "evil") && !strings.HasPrefix(p, h.dir) {
					t.Errorf("file escaped to %s", p)
				}
				return nil
			})
		})
	}
}

func TestManifestMismatchWithAnnouncedSummaryRejected(t *testing.T) {
	blob := []byte(`{"entries":[{"p":"a","s":10}]}`)
	for name, mut := range map[string]func(*protocol.TransferRequest){
		"files": func(r *protocol.TransferRequest) { r.Files = 99 },
		"size":  func(r *protocol.TransferRequest) { r.Size = 1 },
		"hash":  func(r *protocol.TransferRequest) { r.SHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
			if ack := hostileFolder(t, h, blob, mut); ack.OK {
				t.Fatal("accepted a manifest that contradicts the request")
			}
			h.wait()
			assertEmpty(t, h.dir)
		})
	}
}

func TestOversizedManifestBlobRejected(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	conn := h.authedRaw()
	protocol.WriteMsg(conn, &protocol.TransferRequest{Mode: protocol.ModeFolder, Name: "x", SHA256: sum(nil)})
	protocol.Expect[*protocol.TransferResponse](conn)
	conn.Write([]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // claims ~9 exabytes
	if r := h.wait(); r.err == nil {
		t.Fatal("receiver accepted an absurd manifest size")
	}
	assertEmpty(t, h.dir)
}

// rawFolderSession drives a folder transfer by hand so tests can corrupt the data stream.
func rawFolderSession(t *testing.T, h *harness, blob []byte) (conn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
}) {
	t.Helper()
	c := h.authedRaw()
	sum := sha256.Sum256(blob)
	_, plan, err := ParseManifest(blob)
	if err != nil {
		t.Fatal(err)
	}
	protocol.WriteMsg(c, &protocol.TransferRequest{Mode: protocol.ModeFolder, Name: "proj", SHA256: hexOf(sum[:]),
		Size: plan.Total, Files: plan.Files, Dirs: plan.Dirs})
	if resp, err := protocol.Expect[*protocol.TransferResponse](c); err != nil || !resp.Accept {
		t.Fatalf("%+v %v", resp, err)
	}
	protocol.WriteBlob(c, blob)
	if ack, err := protocol.Expect[*protocol.ManifestAck](c); err != nil || !ack.OK {
		t.Fatalf("%+v %v", ack, err)
	}
	return c
}

func TestCorruptTrailerAbortsWholeFolder(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	blob := []byte(`{"entries":[{"p":"a.txt","s":5},{"p":"b.txt","s":5}]}`)
	c := rawFolderSession(t, h, blob)
	a := sha256.Sum256([]byte("hello"))
	c.Write([]byte("hello"))
	c.Write(a[:]) // a.txt is fine
	c.Write([]byte("world"))
	bad := sha256.Sum256([]byte("WORLD"))
	c.Write(bad[:]) // b.txt trailer does not match its bytes
	res, err := protocol.Expect[*protocol.TransferResult](c)
	if err != nil || res.OK {
		t.Fatalf("corruption reported as success: %+v %v", res, err)
	}
	if r := h.wait(); !errors.Is(r.err, ErrVerification) {
		t.Fatalf("%v", r.err)
	}
	assertEmpty(t, h.dir) // not even the good file or the staging dir
}

func TestTruncatedFolderStreamLeavesNothing(t *testing.T) {
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	blob := []byte(`{"entries":[{"p":"a.txt","s":500}]}`)
	c := rawFolderSession(t, h, blob)
	c.Write([]byte("only a little"))
	c.Close()
	if r := h.wait(); r.err == nil {
		t.Fatal("expected error")
	}
	assertEmpty(t, h.dir)
}

func TestFileModifiedAfterScanIsDetectedBySender(t *testing.T) {
	// A receiver that reports a different tree hash must make the sender fail.
	root, _ := mkTree(t)
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	scan, _ := filesystem.Scan(root)
	conn := h.dial()
	o := h.opts(testPIN)
	o.Policy = h.r.Policy
	// Run the real receiver but swap the sender's expectation by corrupting the
	// file after the scan so the sender's own check trips instead.
	os.WriteFile(filepath.Join(root, "main.py"), []byte("changed after scan!!!"), 0o644)
	_, err := SendFolder(context.Background(), conn, h.selfS(), scan, o)
	if err == nil {
		t.Fatal("sender did not notice a file changing after the scan")
	}
	conn.Close()
	h.wait()
	assertEmpty(t, h.dir)
}

func TestSymlinkSwappedInAfterScanIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	root := filepath.Join(t.TempDir(), "proj")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "innocent.txt"), []byte("fine"), 0o644)
	secret := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(secret, []byte("TOP-SECRET-FILE-CONTENTS"), 0o644)

	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	scan, _ := filesystem.Scan(root)
	os.Remove(filepath.Join(root, "innocent.txt"))
	os.Symlink(secret, filepath.Join(root, "innocent.txt")) // swapped after the scan
	o := h.opts(testPIN)
	o.Policy = h.r.Policy
	conn := h.dial()
	_, err := SendFolder(context.Background(), conn, h.selfS(), scan, o)
	if err == nil || !strings.Contains(err.Error(), "no longer a regular file") {
		t.Fatalf("err = %v", err)
	}
	conn.Close() // the CLI closes on error; the receiver must then clean up
	h.wait()
	assertEmpty(t, h.dir)
}

func TestFolderDeclined(t *testing.T) {
	root, _ := mkTree(t)
	h := newHarness(t, ApproverFunc(func(context.Context, Incoming) Decision { return Decision{Reason: "no"} }), security.Policy{})
	if _, err := h.sendFolder(root, testPIN); !errors.Is(err, ErrDeclined) {
		t.Fatalf("%v", err)
	}
	h.wait()
	assertEmpty(t, h.dir)
}

func TestIncomingFolderSummaryShownToApprover(t *testing.T) {
	root, files := mkTree(t)
	got := make(chan Incoming, 1)
	h := newHarness(t, ApproverFunc(func(_ context.Context, in Incoming) Decision {
		got <- in
		return Decision{Accept: true}
	}), security.Policy{})
	if _, err := h.sendFolder(root, testPIN); err != nil {
		t.Fatal(err)
	}
	h.wait()
	in := <-got
	if in.Type != security.TransferFolder || in.Name != "pdf-assistant" || in.Files != len(files) || in.Dirs != 6 || in.Size == 0 {
		t.Fatalf("%+v", in)
	}
}

func TestStalledSenderDoesNotHoldReceiverForever(t *testing.T) {
	old := dataIdleTimeoutForTest(300 * time.Millisecond)
	defer old()
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	blob := []byte(`{"entries":[{"p":"a.txt","s":500}]}`)
	c := rawFolderSession(t, h, blob)
	c.Write([]byte("a few bytes, then silence")) // never closes, never sends more
	start := time.Now()
	r := h.wait()
	if r.err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("receiver did not give up on a stalled sender (err=%v after %v)", r.err, time.Since(start))
	}
	assertEmpty(t, h.dir)
}

// TestExcludedFilesNeverReachTheReceiver is the end-to-end proof for project
// awareness: with the default project rules, secrets and generated folders are
// absent from the manifest AND from the receiver's disk.
func TestExcludedFilesNeverReachTheReceiver(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	for rel, content := range map[string]string{
		"go.mod":                    "module app",
		"main.go":                   "package main",
		".env":                      "API_KEY=SUPER-SECRET-VALUE",
		"config/credentials.json":   `{"key":"SUPER-SECRET-VALUE"}`,
		"node_modules/dep/index.js": "dependency",
		".git/config":               "[core]",
		"src/embedded.py":           `KEY = "AKIAIOSFODNN7ABCDEFG"`,
		"README.md":                 "# app",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	scan, err := filesystem.ScanWith(root, filesystem.ScanOptions{Rules: project.NewRules(root, project.Options{Project: true})})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := NewManifest(scan).Marshal()
	for _, banned := range []string{".env", "credentials", "node_modules", ".git/", "embedded.py"} {
		if strings.Contains(string(blob), banned) {
			t.Fatalf("manifest mentions excluded path %q: %s", banned, blob)
		}
	}
	h := newHarness(t, acceptAll(ConflictRename), security.Policy{})
	o := h.opts(testPIN)
	if _, err := SendFolder(context.Background(), h.dial(), h.selfS(), scan, o); err != nil {
		t.Fatal(err)
	}
	r := h.wait()
	if r.err != nil {
		t.Fatal(r.err)
	}
	filepath.WalkDir(h.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), "SUPER-SECRET-VALUE") || strings.Contains(string(b), "AKIAIOSFODNN7ABCDEFG") {
				t.Errorf("secret content reached the receiver in %s", p)
			}
			if d.Name() == ".env" || d.Name() == "credentials.json" {
				t.Errorf("sensitive file reached the receiver: %s", p)
			}
		}
		return nil
	})
	for _, want := range []string{"main.go", "go.mod", "README.md"} {
		if _, err := os.Stat(filepath.Join(r.rec.Path, want)); err != nil {
			t.Errorf("%s missing", want)
		}
	}
	if _, err := os.Stat(filepath.Join(r.rec.Path, "node_modules")); err == nil {
		t.Error("node_modules was sent")
	}
}

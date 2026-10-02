package transfer

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/thameem/drop/internal/filesystem"
	"github.com/thameem/drop/internal/security"
)

// BenchmarkFileTransfer measures application-level throughput over loopback:
// TLS 1.3, SHA-256 on both ends, disk read and write. Loopback has no network
// limit, so this bounds what drop itself can do, not what a Wi-Fi link will.
func BenchmarkFileTransfer(b *testing.B) {
	const size = 256 << 20
	src := filepath.Join(b.TempDir(), "big.bin")
	data := make([]byte, 1<<20)
	rand.Read(data)
	f, _ := os.Create(src)
	for i := 0; i < size/len(data); i++ {
		f.Write(data)
	}
	f.Close()
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		h := newHarnessB(b)
		b.StartTimer()
		o := h.opts(testPIN)
		o.Policy = h.r.Policy
		if _, err := SendFile(context.Background(), h.dialB(b), h.selfS(), src, o); err != nil {
			b.Fatal(err)
		}
		<-h.done
	}
}

func BenchmarkFolderTransfer(b *testing.B) {
	root := filepath.Join(b.TempDir(), "tree")
	os.MkdirAll(root, 0o755)
	buf := make([]byte, 4096)
	rand.Read(buf)
	for i := 0; i < 2000; i++ {
		os.WriteFile(filepath.Join(root, "f"+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+i/676))), buf, 0o644)
	}
	scan, _ := filesystem.Scan(root)
	b.SetBytes(scan.TotalSize)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		h := newHarnessB(b)
		b.StartTimer()
		o := h.opts(testPIN)
		o.Policy = security.Policy{}
		if _, err := SendFolder(context.Background(), h.dialB(b), h.selfS(), scan, o); err != nil {
			b.Fatal(err)
		}
		<-h.done
	}
}

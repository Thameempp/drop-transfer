package cli

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transfer"
)

func approveWith(t *testing.T, input, dir string) transfer.Decision {
	t.Helper()
	inc := transfer.Incoming{Name: "a.txt", Size: 3, Type: security.TransferFile, Authorized: true, AuthMethod: "trusted"}
	return approve(bufio.NewReader(strings.NewReader(input)), dir, false, inc)
}

func TestApproveDefaultsToConfiguredDir(t *testing.T) {
	d := approveWith(t, "y\n", t.TempDir())
	if !d.Accept || d.Dir != "" {
		t.Fatalf("%+v", d)
	}
}

func TestApproveDChangesFolderForThisTransferOnly(t *testing.T) {
	other := filepath.Join(t.TempDir(), "elsewhere")
	d := approveWith(t, "d\n"+other+"\ny\n", t.TempDir())
	if !d.Accept || d.Dir != other {
		t.Fatalf("%+v", d)
	}
}

func TestApproveDThenDecline(t *testing.T) {
	if d := approveWith(t, "d\n"+t.TempDir()+"\nn\n", t.TempDir()); d.Accept {
		t.Fatalf("%+v", d)
	}
}

func TestApproveDEmptyKeepsFolder(t *testing.T) {
	if d := approveWith(t, "d\n\ny\n", t.TempDir()); !d.Accept || d.Dir != "" {
		t.Fatalf("%+v", d)
	}
}

func TestApproveTextWithoutPrompt(t *testing.T) {
	inc := transfer.Incoming{Name: "", Size: 5, Type: security.TransferText}
	d := approve(bufio.NewReader(strings.NewReader("")), t.TempDir(), false, inc)
	if !d.Accept {
		t.Fatalf("text should be accepted without asking: %+v", d)
	}
}

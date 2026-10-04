package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/thameem/drop/internal/protocol"
	"github.com/thameem/drop/internal/security"
	"github.com/thameem/drop/internal/transport"
)

// MaxClipboardItems bounds how many clipboard entries one transfer carries.
const MaxClipboardItems = 100

type clipboardPayload struct {
	Items []string `json:"items"`
}

// EncodeClipboard packs clipboard entries (newest first) for sending. Entries
// must be non-empty valid UTF-8; the whole payload is limited to MaxTextSize.
func EncodeClipboard(items []string) ([]byte, error) {
	if len(items) == 0 {
		return nil, errors.New("nothing selected")
	}
	if len(items) > MaxClipboardItems {
		return nil, fmt.Errorf("at most %d clipboard entries can be sent at once", MaxClipboardItems)
	}
	data, err := json.Marshal(clipboardPayload{Items: items})
	if err != nil {
		return nil, err
	}
	if len(data) > MaxTextSize {
		return nil, fmt.Errorf("the selected entries are %d bytes; the limit is %d. Select fewer or send a file", len(data), MaxTextSize)
	}
	return data, nil
}

// DecodeClipboard validates and unpacks a received clipboard payload.
func DecodeClipboard(data []byte) ([]string, error) {
	var p clipboardPayload
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid clipboard payload: %w", err)
	}
	if n := len(p.Items); n == 0 || n > MaxClipboardItems {
		return nil, fmt.Errorf("invalid clipboard payload: %d entries", n)
	}
	for _, it := range p.Items {
		if it == "" || !utf8.ValidString(it) {
			return nil, errors.New("invalid clipboard payload: empty or non-text entry")
		}
	}
	return p.Items, nil
}

// SendClipboard sends an EncodeClipboard payload. Clipboard transfers always
// need the PIN or a trusted device (see security.Policy).
func SendClipboard(ctx context.Context, conn transport.Conn, self Self, payload []byte, o SendOptions) (*SendResult, error) {
	if len(payload) > MaxTextSize {
		return nil, fmt.Errorf("clipboard payload is %d bytes; the limit is %d", len(payload), MaxTextSize)
	}
	sum := sha256.Sum256(payload)
	req := &protocol.TransferRequest{TransferID: newID(), Mode: protocol.ModeClipboard, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:])}
	return send(ctx, conn, self, o, security.TransferClipboard, req, func(c transport.Conn) (string, error) {
		return streamBytes(c, bytes.NewReader(payload), req, o.Progress)
	})
}

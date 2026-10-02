package protocol

// Message is any control message.
type Message interface{ MsgType() string }

// Hello opens a connection: the dialer advertises the versions it speaks.
type Hello struct {
	Versions   []int  `json:"versions"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	OS         string `json:"os"`
}

// HelloAck selects the negotiated version.
type HelloAck struct {
	Version    int    `json:"version"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	OS         string `json:"os,omitempty"`
	// Trusted tells the dialer that the listener recognizes its (TLS-verified)
	// key as a trusted device, so PIN authorization may be skipped. It reveals
	// nothing about anyone else.
	Trusted bool `json:"trusted,omitempty"`
}

// Auth messages carry the PIN authorization exchange (PAKE inside the TLS
// channel). See docs/protocol.md. The PIN itself is never sent.

// AuthInit asks the receiver to start PIN authorization.
type AuthInit struct{}

// AuthParams answers AuthInit with the Argon2id parameters the sender needs to
// derive the PAKE password from the PIN, or reports a lockout.
type AuthParams struct {
	Locked     bool   `json:"locked,omitempty"`
	RetryAfter int    `json:"retry_after_secs,omitempty"`
	Salt       []byte `json:"salt,omitempty"`
	Time       uint32 `json:"time,omitempty"`
	MemoryKiB  uint32 `json:"memory_kib,omitempty"`
	Threads    uint8  `json:"threads,omitempty"`
}

// AuthStart carries the sender's PAKE message.
type AuthStart struct {
	Msg []byte `json:"msg"`
}

// AuthChallenge carries the receiver's PAKE message.
type AuthChallenge struct {
	Msg []byte `json:"msg"`
}

// AuthProof is the sender's key-confirmation tag.
type AuthProof struct {
	Tag []byte `json:"tag"`
}

// AuthResult is the receiver's verdict. On success Tag proves the receiver also
// knew the PIN verifier (mutual authentication).
type AuthResult struct {
	OK                bool   `json:"ok"`
	Tag               []byte `json:"tag,omitempty"`
	AttemptsRemaining int    `json:"attempts_remaining,omitempty"`
	RetryAfter        int    `json:"retry_after_secs,omitempty"`
}

// Transfer modes.
const (
	ModeFile   = "file"
	ModeText   = "text"
	ModeFolder = "folder"
)

// TransferRequest describes what the sender wants to send.
type TransferRequest struct {
	TransferID string `json:"transfer_id"`
	Mode       string `json:"mode"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"` // hex; for folders, the hash of the manifest blob
	// Folder summary, shown to the user before anything is sent. The receiver
	// verifies it against the manifest.
	Files int `json:"files,omitempty"`
	Dirs  int `json:"dirs,omitempty"`
}

// ManifestAck tells the sender whether the receiver accepted the manifest.
type ManifestAck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// TransferResponse is the receiver's decision.
type TransferResponse struct {
	Accept bool   `json:"accept"`
	Reason string `json:"reason,omitempty"`
}

// TransferResult is sent by the receiver after all bytes have arrived.
type TransferResult struct {
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256"` // hash the receiver computed
	Error  string `json:"error,omitempty"`
	// Trusted is set when the receiver's user chose to trust the sender during
	// this transfer: later transfers will not need the PIN.
	Trusted bool `json:"trusted,omitempty"`
}

// Error reports a fatal protocol or application error to the peer.
type Error struct {
	Message string `json:"message"`
}

func (*Hello) MsgType() string            { return "hello" }
func (*HelloAck) MsgType() string         { return "hello_ack" }
func (*AuthInit) MsgType() string         { return "auth_init" }
func (*AuthParams) MsgType() string       { return "auth_params" }
func (*AuthStart) MsgType() string        { return "auth_start" }
func (*AuthChallenge) MsgType() string    { return "auth_challenge" }
func (*AuthProof) MsgType() string        { return "auth_proof" }
func (*AuthResult) MsgType() string       { return "auth_result" }
func (*ManifestAck) MsgType() string      { return "manifest_ack" }
func (*TransferRequest) MsgType() string  { return "transfer_request" }
func (*TransferResponse) MsgType() string { return "transfer_response" }
func (*TransferResult) MsgType() string   { return "transfer_result" }
func (*Error) MsgType() string            { return "error" }

func newMessage(t string) Message {
	switch t {
	case "hello":
		return &Hello{}
	case "hello_ack":
		return &HelloAck{}
	case "auth_init":
		return &AuthInit{}
	case "auth_params":
		return &AuthParams{}
	case "auth_start":
		return &AuthStart{}
	case "auth_challenge":
		return &AuthChallenge{}
	case "auth_proof":
		return &AuthProof{}
	case "auth_result":
		return &AuthResult{}
	case "manifest_ack":
		return &ManifestAck{}
	case "transfer_request":
		return &TransferRequest{}
	case "transfer_response":
		return &TransferResponse{}
	case "transfer_result":
		return &TransferResult{}
	case "error":
		return &Error{}
	}
	return nil
}

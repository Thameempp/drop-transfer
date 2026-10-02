package security

// TransferType classifies what is being sent. Authorization decisions are made
// from the type in exactly one place (Policy.RequiresAuthorization) instead of
// being scattered through the CLI.
type TransferType string

const (
	TransferText      TransferType = "text"
	TransferClipboard TransferType = "clipboard"
	TransferFile      TransferType = "file"
	TransferFolder    TransferType = "folder"
	TransferProject   TransferType = "project"
	TransferGit       TransferType = "git"
)

// Policy is the authorization policy. Everything except plain text requires
// the PIN, and unknown types fail closed.
type Policy struct {
	// TextRequiresPIN makes plain-text transfers protected too. Default false
	// keeps `echo hi | drop --text` frictionless.
	TextRequiresPIN bool
}

// RequiresAuthorization reports whether t may only proceed after PIN authentication.
func (p Policy) RequiresAuthorization(t TransferType) bool {
	if t == TransferText {
		return p.TextRequiresPIN
	}
	return true // file, folder, project, git, clipboard, and anything unknown
}

package project

import (
	"bytes"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// Secret detection is a safety net, not a guarantee. It looks at file names and
// at the content of small text files for a handful of well-known credential
// formats. It will miss secrets (custom formats, encoded or split values) and
// can flag harmless files (test fixtures). Never rely on it as the only
// protection.

// sensitiveDirs are directories that hold credentials by convention.
var sensitiveDirs = map[string]string{
	".ssh": "SSH keys folder", ".aws": "AWS credentials folder", ".gnupg": "GPG keys folder",
	".kube": "Kubernetes credentials folder", ".docker": "Docker credentials folder",
}

// safeEnvSuffixes are .env variants that are templates, not secrets.
var safeEnvSuffixes = []string{".example", ".sample", ".template", ".dist", ".defaults", ".schema"}

// SensitiveName reports whether a file name alone suggests credentials.
func SensitiveName(name string) (reason string, ok bool) {
	lower := strings.ToLower(name)
	switch {
	case lower == ".env" || strings.HasPrefix(lower, ".env."):
		for _, s := range safeEnvSuffixes {
			if strings.HasSuffix(lower, s) {
				return "", false
			}
		}
		return "environment file", true
	case strings.HasSuffix(lower, ".pem"), strings.HasSuffix(lower, ".key"), strings.HasSuffix(lower, ".p12"),
		strings.HasSuffix(lower, ".pfx"), strings.HasSuffix(lower, ".jks"), strings.HasSuffix(lower, ".keystore"),
		strings.HasSuffix(lower, ".ppk"):
		return "private key or certificate store", true
	case lower == "id_rsa", lower == "id_dsa", lower == "id_ecdsa", lower == "id_ed25519":
		return "SSH private key", true
	case lower == "credentials.json", strings.HasPrefix(lower, "service-account") && strings.HasSuffix(lower, ".json"),
		strings.HasPrefix(lower, "client_secret") && strings.HasSuffix(lower, ".json"):
		return "cloud credentials file", true
	case lower == ".netrc", lower == "_netrc", lower == ".pgpass", lower == ".htpasswd", lower == ".git-credentials",
		lower == ".pypirc":
		return "credentials file", true
	case lower == "secrets.json", lower == "secrets.yml", lower == "secrets.yaml", lower == "secrets.toml":
		return "secrets file", true
	case strings.HasSuffix(lower, ".tfstate"), strings.HasSuffix(lower, ".tfstate.backup"):
		return "Terraform state (may contain secrets)", true
	}
	return "", false
}

type contentRule struct {
	name string
	re   *regexp.Regexp
}

var contentRules = []contentRule{
	{"private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Stripe live key", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{20,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b`)},
}

// documented example values that must not count as findings.
var exampleValues = [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE"), []byte("EXAMPLE")}

const (
	maxScanBytes = 1 << 20 // larger files are not scanned
	sniffBytes   = 8 << 10
)

// binaryExt are skipped without reading: they are not text and scanning them is wasted work.
var binaryExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".jar": true,
	".mp3": true, ".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".wav": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true, ".o": true, ".a": true,
	".pt": true, ".pth": true, ".onnx": true, ".safetensors": true, ".ckpt": true, ".parquet": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".pyc": true, ".class": true,
}

// ScanContent looks for well-known credential formats in the file at abs. It
// returns the kind of secret found (never the secret itself).
func ScanContent(abs string, size int64) (kind string, found bool) {
	if size > maxScanBytes || size == 0 || binaryExt[strings.ToLower(path.Ext(abs))] {
		return "", false
	}
	f, err := os.Open(abs)
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	if err != nil {
		return "", false
	}
	return scanBytes(data)
}

// ScanText looks for well-known credential formats in text (such as a
// clipboard entry). It returns the kind found, never the secret itself.
func ScanText(text string) (kind string, found bool) {
	if len(text) > maxScanBytes {
		return "", false
	}
	return scanBytes([]byte(text))
}

func scanBytes(data []byte) (kind string, found bool) {
	head := data
	if len(head) > sniffBytes {
		head = head[:sniffBytes]
	}
	if bytes.IndexByte(head, 0) >= 0 { // binary
		return "", false
	}
	for _, r := range contentRules {
		for _, loc := range r.re.FindAllIndex(data, 8) {
			if !isExample(data[loc[0]:loc[1]]) {
				return r.name, true
			}
		}
	}
	return "", false
}

func isExample(b []byte) bool {
	for _, e := range exampleValues {
		if bytes.Contains(bytes.ToUpper(b), bytes.ToUpper(e)) {
			return true
		}
	}
	return false
}

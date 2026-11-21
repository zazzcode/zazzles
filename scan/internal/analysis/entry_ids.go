package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// SnapshotRecordID creates a versioned snapshot-local identity from source, owner
// and a lexical/derived discriminator. Owners distinguish server/schema instances
// for entries and lexical module scopes for callables. Derived records use their
// binding/context inputs as discriminators. Neither judgments nor excerpts belong
// in these keys. IDs are not edit-stable finding fingerprints.
func SnapshotRecordID(namespace string, source Evidence, owner, discriminator string) (string, error) {
	switch namespace {
	case "entry", "registration", "dispatch", "callable", "invocation", "candidate":
	default:
		return "", fmt.Errorf("unsupported record namespace %q", namespace)
	}
	if owner == "" {
		return "", fmt.Errorf("record owner is required")
	}
	if err := validateEntrySource(source); err != nil {
		return "", err
	}
	// JSON provides length-delimited fields; concatenating arbitrary owner/scope
	// strings would admit ambiguous keys when a delimiter occurs in source names.
	key := struct {
		Version                                       int
		Namespace, File, SHA256, Owner, Discriminator string
		StartByte, EndByte                            int
	}{1, namespace, source.Span.File, source.SHA256, owner, discriminator, source.Span.StartByte, source.Span.EndByte}
	data, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return namespace + ":v1:" + hex.EncodeToString(sum[:]), nil
}

func validateEntrySource(e Evidence) error {
	s := e.Span
	if s.File == "" || s.File == "." || path.IsAbs(s.File) || strings.Contains(s.File, "\\") || strings.Contains(s.File, ":") || path.Clean(s.File) != s.File || strings.HasPrefix(s.File, "../") {
		return fmt.Errorf("source path must be normalized repository-relative slash path: %q", s.File)
	}
	if s.StartByte < 0 || s.EndByte < s.StartByte || s.StartLine < 1 || s.EndLine < s.StartLine {
		return fmt.Errorf("invalid source span for %q", s.File)
	}
	hash, err := hex.DecodeString(e.SHA256)
	if err != nil || len(hash) != sha256.Size || strings.ToLower(e.SHA256) != e.SHA256 {
		return fmt.Errorf("source sha256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}

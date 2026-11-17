// Package lang maps file extensions to the languages scan can parse.
//
// It is deliberately the only place that knows about extensions. Adding a
// language means adding a grammar, query sets, and a resolver; this registry is
// the seam the walker uses to decide what is worth reading.
package lang

import (
	"path/filepath"
	"strings"
)

// Language identifies a supported source language.
type Language string

// The languages in the initial release set. Order here carries no meaning; the
// implementation order is TypeScript/JavaScript, then Python, then Go and Java.
const (
	TypeScript Language = "typescript"
	JavaScript Language = "javascript"
	Python     Language = "python"
	PHP        Language = "php"
	Go         Language = "go"
	Java       Language = "java"
)

// extensions maps a lower-case file extension, including the dot, to a language.
var extensions = map[string]Language{
	".ts":    TypeScript,
	".tsx":   TypeScript,
	".mts":   TypeScript,
	".cts":   TypeScript,
	".js":    JavaScript,
	".jsx":   JavaScript,
	".mjs":   JavaScript,
	".cjs":   JavaScript,
	".vue":   JavaScript,
	".py":    Python,
	".php":   PHP,
	".phtml": PHP,
	".go":    Go,
	".java":  Java,
}

// Detect returns the language for a path, and whether scan supports it.
//
// Detection is by extension only. Content sniffing is deliberately out of scope:
// a file with an unsupported extension is skipped and counted, never guessed at.
func Detect(path string) (Language, bool) {
	language, ok := extensions[strings.ToLower(filepath.Ext(path))]
	return language, ok
}

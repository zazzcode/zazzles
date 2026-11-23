// Package deployconf reads allow-listed deployment files as text.
// It does not execute anything and does not expand variables.
package deployconf

// MaxFile is the per-file read limit.
const MaxFile = 256 << 10

// Directive is one parsed directive and the scope it was written in.
type Directive struct {
	File   string
	Line   int
	Name   string
	Values []string
	// Scope is the Apache directory path or the nginx "location <path>".
	// It is empty at server scope.
	Scope string
	// ScopeLine is the line that opens Scope, or 0 at server scope.
	ScopeLine int
	// Dir is the container directory an nginx scope serves: the root in
	// force joined with a prefix location. It is empty when no root is
	// stated or the location is a pattern.
	Dir string
	// Effective is the Apache Options list in force after this directive.
	Effective []string
}

// Gap is a file or operand the reader could not use.
type Gap struct {
	Kind, Detail, File string
	Line               int
}

// Ownership is a chown, chmod or COPY --chown that changes a container path.
type Ownership struct {
	File, User, Path, Mode string
	Line                   int
	Recursive              bool
}

// ScheduleLine is one cron job.
type ScheduleLine struct {
	File, User, Command string
	Line                int
	System              bool
}

// PathMapping is one COPY or ADD destination and the project path it holds.
type PathMapping struct {
	Dst, Src string
	Line     int
}

// CronInstall is a `crontab <file>` instruction and the user in force there.
type CronInstall struct {
	File, User, Path string
	Line             int
}

// EnvSetting is one kept environment key with the line that sets it.
type EnvSetting struct {
	Key, Value string
	Line       int
}

func unread(file string) []Gap {
	return []Gap{{Kind: "config_file_unread", Detail: "file exceeds 256 KiB or is unreadable", File: file, Line: 1}}
}

func tooBig(src []byte) bool { return len(src) > MaxFile }

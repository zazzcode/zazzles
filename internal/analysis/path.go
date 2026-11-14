package analysis

import "fmt"

// Path operand slots. The effective file path, the data written through it and
// operation options are separate claim slots; only the path slot is a path source.
const (
	PathSlotFile    = "path"
	PathSlotContent = "content"
	PathSlotOption  = "option"
	// PathSlotArchive is the archive whose stored entry names become path components.
	PathSlotArchive = "archive"
)

// Path guard kinds classify a control that mentions a path value. Only the
// enforcing kinds can establish containment, and only with the same value and
// a rejecting branch that terminates before use; adequacy is judged separately.
const (
	PathGuardAllowlist          = "allowlist"
	PathGuardPrefixBoundary     = "prefix_boundary"
	PathGuardPrefixBare         = "prefix_bare"
	PathGuardRelative           = "relative"
	PathGuardCommonPath         = "commonpath"
	PathGuardDotDotText         = "dotdot_text"
	PathGuardPresenceOrType     = "presence_or_type"
	PathGuardComponentSanitizer = "component_sanitizer"
	PathGuardFrameworkRoot      = "framework_root"
	PathGuardLibraryEntryCheck  = "library_entry_check"
	PathGuardSeparatorText      = "separator_text"
	PathGuardUnclassified       = "unclassified"
	PathGuardSubstring          = "substring"
	PathTransformRealpath       = "realpath"
	PathTransformDecode         = "decode"
	PathTransformJoin           = "join"
	PathTransformResolve        = "resolve"
	PathTransformNormalize      = "normalize"
	PathTransformReduce         = "reduce"
	PathTransformConcat         = "concat"
	PathTransformTemplate       = "template"
	PathTransformAbsolutize     = "absolutize"
	PathTransformPathObject     = "path_object"
	PathTransformStringShape    = "string_operation"
	PathTransformSanitize       = "sanitize_component"
)

// PathFacts describes one filesystem path use independently of language.
// Parser adapters establish every field from source; judgment and report code
// never infer them. Dependency indices refer to CandidateUse.Dependencies and
// context indices to CandidateUse.Context, so no second source store exists.
type PathFacts struct {
	Operation  string `json:"operation"`
	ContractID string `json:"contract_id"`
	// Platform is a declared analysis assumption ("posix"), never inferred from the scanner host.
	Platform string `json:"platform"`
	// Role is read, write or unknown (a dynamic mode); it never changes which operand is the path.
	Role     string        `json:"role"`
	Operands []PathOperand `json:"operands"`
	Paths    []PathFlow    `json:"paths"`
	Guards   []PathGuard   `json:"guards"`
	// Extractor records the library behind an archive extraction and what its declared
	// version establishes about entry-name validation.
	Extractor *PathExtractor `json:"extractor,omitempty"`
}

// PathExtractor is the dependency fact for an archive extraction. Assessment is
// vulnerable_version (a release known to write entry names unchecked), fixed_version
// (a release that rejects names escaping the destination) or unknown_version (a range,
// a missing or unparseable declaration), or caller_entry_path (a verified archive
// reader exposes names and caller code selects a separate write destination).
type PathExtractor struct {
	Library    string `json:"library"`
	Declared   string `json:"declared,omitempty"`
	Assessment string `json:"assessment"`
	// Context indexes the dependency-declaration evidence, when one was found.
	Context int `json:"context"`
}

// PathOperand is one effective operand slot of the filesystem call.
type PathOperand struct {
	Slot         string `json:"slot"`
	Dependencies []int  `json:"dependencies,omitempty"`
	Context      []int  `json:"context,omitempty"`
	Constant     string `json:"constant,omitempty"`
	Dynamic      bool   `json:"dynamic,omitempty"`
}

// PathFlow is one request-source-to-path-operand flow. Raw flows reach the slot
// without a source-backed control; guarded flows name controls that mention the
// value (adequacy is judged separately, never assumed); unknown flows have an
// unresolved transfer or helper. No global safe bit exists.
type PathFlow struct {
	Dependency int    `json:"dependency"`
	Operand    string `json:"operand"`
	Protection string `json:"protection"`
	// Controls index PathFacts.Guards.
	Controls []int  `json:"controls,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Transforms are the path-shaping steps observed in source order within the
	// operand expression and its value chain (join, resolve, normalize, decode...).
	Transforms []string `json:"transforms,omitempty"`
	// Root is the constant base segment of a join/resolve construction, when one
	// is source-established; it is a candidate trusted root, not proof of containment.
	Root string `json:"root,omitempty"`
	// DecodedAfterGuard is true when a decoding step on this value follows a
	// control that mentions it, so the control inspected the pre-decoded text.
	DecodedAfterGuard bool `json:"decoded_after_guard,omitempty"`
}

// PathGuard is one source-backed control mentioning a path value.
type PathGuard struct {
	// Context indexes CandidateUse.Context.
	Context int    `json:"context"`
	Kind    string `json:"kind"`
}

func pathEnforcingKind(kind string) bool {
	switch kind {
	case PathGuardAllowlist, PathGuardPrefixBoundary, PathGuardRelative, PathGuardCommonPath, PathGuardComponentSanitizer, PathGuardFrameworkRoot, PathGuardLibraryEntryCheck:
		return true
	}
	return false
}

// EnforcingPathGuard reports whether a control kind can establish containment
// when it checks the same value on a rejecting, terminating branch.
func EnforcingPathGuard(kind string) bool { return pathEnforcingKind(kind) }

// KnownNonEnforcingPathGuard reports a recognized control that does not
// establish containment (text blacklists, presence and type tests).
func KnownNonEnforcingPathGuard(kind string) bool {
	return kind == PathGuardDotDotText || kind == PathGuardPresenceOrType || kind == PathGuardSubstring
}

// Validate checks every index and enumerated value against the candidate use.
func (p *PathFacts) Validate(deps, context int) error {
	if p == nil {
		return nil
	}
	if p.Platform != "posix" {
		return fmt.Errorf("unsupported path platform assumption %q", p.Platform)
	}
	switch p.Role {
	case "read", "write", "delete", "unknown":
	default:
		return fmt.Errorf("invalid path operation role %q", p.Role)
	}
	slots := map[string]bool{}
	for _, o := range p.Operands {
		switch o.Slot {
		case PathSlotFile, PathSlotContent, PathSlotOption, PathSlotArchive:
		default:
			return fmt.Errorf("invalid path operand slot %q", o.Slot)
		}
		if slots[o.Slot] {
			return fmt.Errorf("duplicate path operand slot %q", o.Slot)
		}
		slots[o.Slot] = true
		for _, i := range o.Dependencies {
			if i < 0 || i >= deps {
				return fmt.Errorf("path operand %s dependency %d out of range", o.Slot, i)
			}
		}
		for _, i := range o.Context {
			if i < 0 || i >= context {
				return fmt.Errorf("path operand %s context %d out of range", o.Slot, i)
			}
		}
	}
	if !slots[PathSlotFile] {
		return fmt.Errorf("path facts lack the effective path operand")
	}
	if e := p.Extractor; e != nil {
		switch e.Assessment {
		case "vulnerable_version", "fixed_version", "unknown_version", "caller_entry_path":
		default:
			return fmt.Errorf("invalid extractor assessment %q", e.Assessment)
		}
		if e.Context < 0 || e.Context >= context {
			return fmt.Errorf("extractor context %d out of range", e.Context)
		}
	}
	for _, g := range p.Guards {
		if g.Context < 0 || g.Context >= context {
			return fmt.Errorf("path guard context %d out of range", g.Context)
		}
		switch g.Kind {
		case PathGuardAllowlist, PathGuardPrefixBoundary, PathGuardPrefixBare, PathGuardRelative, PathGuardCommonPath, PathGuardDotDotText, PathGuardPresenceOrType, PathGuardUnclassified, PathGuardComponentSanitizer, PathGuardFrameworkRoot, PathGuardLibraryEntryCheck, PathGuardSeparatorText, PathGuardSubstring:
		default:
			return fmt.Errorf("invalid path guard kind %q", g.Kind)
		}
	}
	for _, f := range p.Paths {
		if f.Dependency < 0 || f.Dependency >= deps || (f.Operand != PathSlotFile && f.Operand != PathSlotArchive) {
			return fmt.Errorf("path flow references a missing dependency or a non-path operand")
		}
		switch f.Protection {
		case "raw", "guarded", "unknown":
		default:
			return fmt.Errorf("invalid path flow protection %q", f.Protection)
		}
		for _, i := range f.Controls {
			if i < 0 || i >= len(p.Guards) {
				return fmt.Errorf("path flow control %d out of range", i)
			}
		}
	}
	return nil
}

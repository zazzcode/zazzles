package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// Request superglobal element state (judge evidence quality V). Page code may
// check a request element against an allow-list and overwrite it when the
// check fails (DVWA's security-level cookie). After that, a read of the
// element is the checked or written value, not fresh request input. The state
// lives in f.globals under its own prefix, so branch merges join it and a
// helper both sees and propagates it, like $GLOBALS writes.

const phpSuperglobalPrefix = "\x01superglobal:"

// phpSuperglobalKey is the state key of a literal element of a request
// superglobal whose writes are modeled. $_SERVER keys and $_SESSION (storage)
// keep their own handling.
func phpSuperglobalKey(name, key string) (string, bool) {
	if prefix := phpRequestElementPrefix(name); prefix != "" && key != "" {
		return prefix + key, true
	}
	return "", false
}

func phpRequestElementPrefix(name string) string {
	switch name {
	case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
		return phpSuperglobalPrefix + name + phpElementSeparator
	}
	return ""
}

// superglobalRead reads a tracked element: its state, joined with fresh
// request input when some path reaching here neither wrote nor checked it.
func (f *phpFlow) superglobalRead(n *sitter.Node, state phpValue, container, origin, key string) phpValue {
	fresh := state.superglobalFresh
	state.superglobalFresh = false
	v := phpTransfer(state, f.module.evidence("value_reference", n))
	if fresh {
		v = phpJoin(v, f.source(n, container, origin, key))
	}
	return v
}

// narrowSuperglobals applies the protections a branch condition implies to
// the request elements it tests. The branch holds only where the condition
// has that truth, so the narrowing is sound for that branch whether or not
// the other one terminates.
func (f *phpFlow) narrowSuperglobals(test *sitter.Node, protections map[string]string, guard analysis.Evidence) {
	for name, protection := range protections {
		base, index, element := strings.Cut(name, phpElementSeparator)
		if !element {
			continue
		}
		sg, ok := phpSuperglobalKey(base, index)
		if !ok {
			continue
		}
		container, origin, _ := superscriptOrigin(base)
		var at *sitter.Node
		phpWalk(test, func(n *sitter.Node) {
			if at == nil && phpElementKey(f.module, n) == name {
				at = n
			}
		})
		if at == nil {
			continue
		}
		v, tracked := f.globals[sg]
		switch {
		case !tracked:
			v = f.source(at, container, origin, index)
		case v.superglobalFresh:
			v.superglobalFresh = false
			v = phpJoin(v, f.source(at, container, origin, index))
		}
		f.setSuperglobal(sg, phpGuarded(v, protection, guard))
	}
}

// superglobalState copies the tracked request elements of a flow, for a
// helper that reads or writes them.
func superglobalState(globals map[string]phpValue) map[string]phpValue {
	out := map[string]phpValue{}
	for k, v := range globals {
		if strings.HasPrefix(k, phpSuperglobalPrefix) {
			out[k] = v
		}
	}
	return out
}

func (f *phpFlow) setSuperglobal(key string, v phpValue) {
	if f.globals == nil {
		f.globals = map[string]phpValue{}
	}
	f.globals[key] = v
	f.markDirty(phpGlobalsKeyPrefix + key)
}

// Replacing the container also replaces every individually tracked element.
func (f *phpFlow) replaceSuperglobalElements(name string, v phpValue, at *sitter.Node) {
	prefix := phpRequestElementPrefix(name)
	if prefix == "" {
		return
	}
	for key := range f.globals {
		if field, ok := strings.CutPrefix(key, prefix); ok {
			f.setSuperglobal(key, f.projectValue(v, field, at))
		}
	}
}

// A dynamic subscript can overwrite any previously tracked element of the
// same container. Each of those reads may still see its earlier value.
func (f *phpFlow) writeSuperglobalElement(name string, index *sitter.Node, v phpValue) bool {
	prefix := phpRequestElementPrefix(name)
	if prefix == "" || index == nil {
		return false
	}
	key, known := phpStringLiteral(f.module, index)
	switch index.Kind() {
	case "integer":
		key, known = phpText(f.module, index), true
	case "variable_name":
		candidate := f.env[phpVarName(f.module, index)]
		if phpLiteralsOnly(candidate) && len(candidate.literals) == 1 {
			key, known = candidate.literals[0].text, true
		}
	}
	if known {
		if key != "" {
			f.setSuperglobal(prefix+key, v)
		}
		return true
	}
	for key, prior := range f.globals {
		if strings.HasPrefix(key, prefix) {
			joined := phpJoin(prior, v)
			joined.superglobalFresh = prior.superglobalFresh
			f.setSuperglobal(key, joined)
		}
	}
	return true
}

// Branch clones within a helper share this collector. A return from an
// included file does not return to the helper's caller.
type phpSuperglobalExits struct {
	includeDepth int
	changed      map[string]bool
	states       []map[string]phpValue
}

func (f *phpFlow) joinHelperExits(terminated bool) {
	exits := f.helperExits
	if len(exits.states) == 0 || len(exits.changed) == 0 {
		return
	}
	if !terminated {
		exits.states = append(exits.states, f.globals)
	}
	for key := range exits.changed {
		var joined phpValue
		fresh := false
		for _, state := range exits.states {
			v, ok := state[key]
			fresh = fresh || !ok || v.superglobalFresh
			joined = phpJoin(joined, v)
		}
		joined.superglobalFresh = fresh
		joined.gaps = phpMergeGaps(nil, joined.gaps)
		f.setSuperglobal(key, joined)
	}
}

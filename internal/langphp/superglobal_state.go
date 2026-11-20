package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
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
	switch name {
	case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
		if key != "" {
			return phpSuperglobalPrefix + name + phpElementSeparator + key, true
		}
	}
	return "", false
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
func (f *phpFlow) narrowSuperglobals(test *sitter.Node, protections map[string]string) {
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
		if f.globals == nil {
			f.globals = map[string]phpValue{}
		}
		f.globals[sg] = phpProtect(v, protection)
		f.markDirty(phpGlobalsKeyPrefix + sg)
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

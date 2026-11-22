package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func (f *phpFlow) phpLoggingMethod(n *sitter.Node, receiver phpValue, method string, nodes []*sitter.Node, values []phpValue) bool {
	switch strings.ToLower(receiver.class) {
	case `psr\log\loggerinterface`, `monolog\logger`:
	default:
		return false
	}
	var messageSlot uint
	switch strings.ToLower(method) {
	case "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency":
	case "log":
		messageSlot = 1
	default:
		return false
	}

	messageNode, message := f.deserializationArgument(n, nodes, values, messageSlot, "message")
	contextNode, context := f.deserializationArgument(n, nodes, values, messageSlot+1, "context")
	if messageNode != nil {
		message = phpTransfer(message, f.module.evidence("log_argument", messageNode))
	}
	if contextNode != nil {
		context = phpTransfer(context, f.module.evidence("log_argument", contextNode))
	}
	f.phpLogUse(n, phpCombine(phpSlot(message, "message"), phpSlot(context, "context")))
	return true
}

func (f *phpFlow) phpLoggingFunction(n *sitter.Node, name string, nodes []*sitter.Node, values []phpValue) bool {
	callee := phpCallee(n)
	if !strings.EqualFold(name, "error_log") || callee == nil || !f.set.phpDeserializationBuiltin(f.module, callee) {
		return false
	}
	if arg, message := f.deserializationArgument(n, nodes, values, 0, "message"); arg != nil {
		message = phpTransfer(message, f.module.evidence("log_argument", arg))
		f.phpLogUse(n, phpSlot(message, "message"))
	}
	return true
}

func (f *phpFlow) phpLogUse(n *sitter.Node, value phpValue) {
	var claims []analysis.Gap
	for _, d := range value.deps {
		container, key := phpLogOrigin(d)
		class, hint := parse.LogDataClass(container, key)
		if container == "session" {
			class = "container"
		}
		if class == "" {
			continue
		}

		kind, detail := "log_sensitive_field_hint", hint+" field hint: "+key
		switch {
		case d.protection == "non_content":
			kind, detail = "log_non_content_only", "only a derived non-content fact is emitted"
		case d.protection == "unknown":
			kind, detail = "log_transform_unresolved", "unmodeled content transformation"
		case class == "protocol_credential":
			kind, detail = "log_protocol_credential", "HTTP credential content is emitted"
		case class == "container":
			kind, detail = "log_request_container", "whole request/session container may include sensitive data"
		}
		claims = append(claims, f.gap(kind, detail, n))
	}
	if len(claims) == 0 {
		return
	}

	u := f.addUse("log_sink_candidate", n, value)
	u.Context = append(u.Context, f.module.evidence("logger_binding", phpCallee(n)))
	u.Gaps = append(u.Gaps, claims...)
	u.Gaps = append(u.Gaps, f.gap("log_destination_unresolved", "logger handlers/formatters/retention are unresolved", n))
}

func phpLogOrigin(d phpDep) (string, string) {
	if _, field, stored := strings.Cut(d.dep.StorageKey, "."); stored {
		return "stored", field
	}
	container, key := strings.ToLower(d.container), d.key
	switch container {
	case "get":
		container = "query"
	case "post", "request", "input":
		container = "body"
	case "cookie":
		container = "cookies"
	case "_session":
		container = "session"
	case "server":
		if header, ok := strings.CutPrefix(key, "HTTP_"); ok {
			return "headers", strings.ReplaceAll(header, "_", "-")
		}
	}
	return container, key
}

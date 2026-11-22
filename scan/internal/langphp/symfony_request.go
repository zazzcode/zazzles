package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const symfonyRequestClass = `Symfony\Component\HttpFoundation\Request`
const symfonyUploadedFileClass = `Symfony\Component\HttpFoundation\File\UploadedFile`

func symfonyRequestProperty(receiver phpValue, name string) (phpValue, bool) {
	if receiver.binding != "symfony_request" {
		return phpValue{}, false
	}
	switch name {
	case "query", "request", "attributes", "cookies", "headers", "files", "server":
		return phpValue{binding: "symfony_bag", driver: name}, true
	}
	return phpValue{}, false
}

func (f *phpFlow) requestCall(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	key := ""
	if len(values) > 0 {
		key, _ = phpSQLText(values[0])
	}
	switch receiver.binding {
	case "symfony_request":
		switch method {
		case "getPayload":
			return phpValue{binding: "symfony_bag", driver: "body"}, true
		case "toArray":
			return phpValue{binding: "symfony_body_array"}, true
		case "getContent":
			return f.source(n, "body", "http.body", ""), true
		case "get":
			return f.source(n, "any", "http.path_query_or_form", key), true
		case "getUri", "getRequestUri", "getPathInfo", "getQueryString", "getSchemeAndHttpHost":
			return f.source(n, "url", "http.url", method), true
		case "getHost", "getClientIp", "getClientIps":
			return f.source(n, "headers", "http.headers", method), true
		case "getMethod", "isMethod":
			return phpValue{unknown: true}, true
		}
	case "symfony_bag":
		switch method {
		case "get":
			return f.symfonyBagInput(n, receiver.driver, key), true
		case "all":
			switch receiver.driver {
			case "query", "request":
				return f.symfonyBagInput(n, receiver.driver, key), true
			}
		case "has":
			if receiver.driver == "query" {
				return f.symfonyBagInput(n, receiver.driver, key), true
			}
		case "getInt", "getBoolean", "getDigits", "getAlpha", "getAlnum", "getEnum":
			if receiver.driver == "files" {
				return phpValue{}, false
			}
			v := f.symfonyBagInput(n, receiver.driver, key)
			v = phpTransfer(v, f.module.evidence("typed_conversion", n))
			if method == "getInt" || method == "getDigits" {
				v = phpProtect(v, "numeric")
			}
			return v, true
		}
	case "symfony_upload":
		origin := ""
		switch method {
		case "getClientOriginalName", "getClientOriginalExtension":
			origin = "http.upload_filename"
		case "getClientMimeType":
			origin = "http.upload_content_type"
		case "getContent", "guessExtension", "getMimeType":
			origin = "http.upload_content"
		case "getPathname", "getRealPath":
			return phpValue{evidence: receiver.evidence}, true
		}
		if origin != "" {
			v := f.source(n, "files", origin, receiver.driver)
			if method == "guessExtension" || method == "getMimeType" {
				v = phpTransfer(v, f.module.evidence("content_derived", n))
			}
			return v, true
		}
	}
	return phpValue{}, false
}

func (f *phpFlow) symfonyBagInput(n *sitter.Node, bag, key string) phpValue {
	switch bag {
	case "query":
		return f.source(n, bag, "http.query", key)
	case "request":
		return f.source(n, bag, "http.form", key)
	case "body":
		return f.source(n, bag, "http.body", key)
	case "attributes":
		return f.source(n, bag, "http.path", key)
	case "cookies":
		return f.source(n, bag, "http.cookies", key)
	case "headers":
		return f.source(n, bag, "http.headers", key)
	case "server":
		if phpServerDetermined(key) {
			return phpValue{evidence: []analysis.Evidence{f.module.evidence("server_value", n)}}
		}
		return f.source(n, "SERVER", serverKeyOrigin(key), key)
	case "files":
		v := f.source(n, bag, "http.upload", key)
		v.binding, v.class, v.driver = "symfony_upload", symfonyUploadedFileClass, key
		return v
	}
	return phpValue{}
}

func (f *phpFlow) symfonyMethodCondition(test *sitter.Node) (bool, bool) {
	if f.symfony == nil || f.entry.HTTP == nil || f.entry.HTTP.Method == "" || test == nil {
		return false, false
	}
	requestMethod := func(n *sitter.Node, name string) bool {
		if n == nil || n.Kind() != "member_call_expression" || phpText(f.module, phpField(n, "name")) != name {
			return false
		}
		receiver := phpField(n, "object")
		return f.env[phpVarName(f.module, receiver)].binding == "symfony_request"
	}
	if requestMethod(test, "isMethod") {
		args := phpArgs(test)
		if len(args) == 1 {
			method, ok := phpStringLiteral(f.module, args[0])
			return strings.EqualFold(method, f.entry.HTTP.Method), ok
		}
	}
	if test.Kind() == "binary_expression" {
		op := phpOperator(f.module, test)
		switch op {
		case "==", "===", "!=", "!==":
			left, right := phpField(test, "left"), phpField(test, "right")
			if requestMethod(right, "getMethod") {
				left, right = right, left
			}
			if requestMethod(left, "getMethod") && len(phpArgs(left)) == 0 {
				method, ok := phpStringLiteral(f.module, right)
				equal := strings.EqualFold(method, f.entry.HTTP.Method)
				return equal != strings.HasPrefix(op, "!"), ok
			}
		}
	}
	return false, false
}

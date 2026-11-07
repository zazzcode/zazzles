package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"strings"
)

func (f *pythonFlow) frameworkCall(n *sitter.Node, q string, nodes []*sitter.Node, values []pythonValue, all pythonValue) (pythonValue, bool) {
	m := f.module
	switch q {
	case "flask.request.get_json":
		return f.source(n, "json", ""), true
	case "sqlite3.connect", "psycopg.connect", "psycopg2.connect", "pymysql.connect", "mysql.connector.connect":
		return pythonValue{binding: "db_connection", driver: strings.TrimSuffix(q, ".connect"), evidence: []analysis.Evidence{m.evidence("sink_binding", n)}}, true
	case "flask.redirect", "flask.send_file", "flask.send_from_directory":
		return pythonValue{rendered: true, binding: "non_html"}, true
	case "flask.jsonify":
		v := all
		v.binding = "json"
		v.rendered = true
		return v, true
	case "flask.render_template":
		f.renderTemplate(n)
		return pythonValue{rendered: true}, true
	case "flask.render_template_string":
		if len(values) > 0 {
			v := values[0]
			if len(v.deps) > 0 {
				f.recordXSS(m.evidence("template_source", nodes[0]), v, "html_text", []analysis.Evidence{m.evidence("render_binding", n)})
			} else if v.constant {
				f.renderInline(n, v.literal)
			}
		}
		return pythonValue{rendered: true}, true
	case "markupsafe.escape", "html.escape":
		result := all
		result.deps = append([]pythonDep{}, all.deps...)
		for i := range result.deps {
			d := &result.deps[i]
			if q == "markupsafe.escape" && pythonMarkupPath(d.dep) {
				continue
			}
			d.protection = "encoded"
			if option := pyKeywordIn(m, n, "quote"); q == "html.escape" && option != nil && pyText(m, option) != "True" {
				d.protection = "text_encoded"
			}
		}
		return pyTransfer(result, m.evidence("html_encoder", n)), true
	case "markupsafe.Markup":
		return pyTransfer(all, m.evidence("trusted_html_wrapper", n)), true
	case "fastapi.responses.HTMLResponse", "starlette.responses.HTMLResponse":
		v := all
		f.recordXSS(m.evidence("html_response", n), v, "html_text", nil)
		v.rendered = true
		return v, true
	case "django.http.HttpResponse", "pyramid.response.Response", "aiohttp.web.Response":
		// Django and Pyramid default to text/html; aiohttp must state it.
		v := all
		if content := pyKeywordIn(m, n, "content_type"); content != nil || q == "aiohttp.web.Response" {
			if literal, ok := pyLiteral(m, content); !ok || !strings.HasPrefix(literal, "text/html") {
				v.rendered = true
				v.binding = "non_html"
				return v, true
			}
		}
		f.recordXSS(m.evidence("html_response", n), v, "html_text", nil)
		v.rendered = true
		return v, true
	case "fastapi.responses.JSONResponse", "starlette.responses.JSONResponse":
		v := all
		v.binding = "json"
		v.rendered = true
		return v, true
	case "jinja2.Template":
		v := pythonValue{}
		if len(values) > 0 {
			v = values[0]
		}
		v.templateEscape = "raw"
		if option := pyKeywordIn(m, n, "autoescape"); option != nil {
			switch pyText(m, option) {
			case "True":
				v.templateEscape = "encoded"
			case "False":
			default:
				v.templateEscape = "unknown"
			}
		}
		v.binding = "jinja_template"
		return pyTransfer(v, m.evidence("template_source_construction", n)), true
	}
	return pythonValue{}, false
}

func (f *pythonFlow) outboundCall(n *sitter.Node, q string, fn *sitter.Node, values []pythonValue) pythonValue {
	m := f.module
	destination := pythonValue{}
	index := 0
	if strings.HasSuffix(q, ".request") {
		index = 1
	}
	if len(values) > index {
		destination = values[index]
	}
	if keyword := pyKeywordIn(m, n, "url"); keyword != nil {
		destination = f.eval(keyword)
	}
	requestDependent := false
	for _, d := range destination.deps {
		requestDependent = requestDependent || d.dep.Source.Kind == "input_source" || d.dep.Source.Kind == "external_response_source" || d.dep.Source.Kind == "storage_source"
	}
	if requestDependent {
		u := f.addUse("outbound_http_candidate", n, destination)
		u.Context = append(u.Context, m.evidence("sink_binding", fn))
		u.APIModel = analysispacks.OutboundContract(strings.Split(q, ".")[0])
	}
	return pythonValue{binding: "http_response", evidence: []analysis.Evidence{m.evidence("external_exchange", n)}}
}

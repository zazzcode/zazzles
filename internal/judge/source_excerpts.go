package judge

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zazzcode/zazzles/internal/analysis"
)

type wireEvidence struct {
	analysis.Evidence
	TextRef     string `json:"text_ref,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

// Source text is shared without merging evidence roles or dropping containing
// controls. Merging uses snapshot byte coordinates before masked-space reduction;
// line ranges and excerpt character columns locate the model-facing witnesses.
func sharedSourceExcerpts(table []analysis.Evidence) ([]wireEvidence, []analysis.Evidence) {
	original := table
	table = append([]analysis.Evidence(nil), table...)
	for i := range table {
		if table[i].ModelText != "" {
			table[i].Text = table[i].ModelText
		}
		table[i].ModelText = ""
	}
	order := make([]int, 0, len(table))
	for i, e := range table {
		if e.Text != "" && e.SHA256 != "" && e.Span.File != "" && len(e.Text) == e.Span.EndByte-e.Span.StartByte {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := table[order[a]], table[order[b]]
		if x.Span.File != y.Span.File {
			return x.Span.File < y.Span.File
		}
		if x.SHA256 != y.SHA256 {
			return x.SHA256 < y.SHA256
		}
		if x.Span.StartByte != y.Span.StartByte {
			return x.Span.StartByte < y.Span.StartByte
		}
		return x.Span.EndByte > y.Span.EndByte
	})
	excerpts := []analysis.Evidence{}
	originals := []string{}
	refs := map[int]int{}
	for _, i := range order {
		e := table[i]
		matched := false
		if len(excerpts) > 0 {
			j := len(excerpts) - 1
			p := &excerpts[j]
			if p.Span.File == e.Span.File && p.SHA256 == e.SHA256 && e.Span.StartByte >= p.Span.StartByte && e.Span.StartByte <= p.Span.EndByte {
				overlap := p.Span.EndByte - e.Span.StartByte
				if overlap > len(e.Text) {
					overlap = len(e.Text)
				}
				start := e.Span.StartByte - p.Span.StartByte
				if p.Text[start:start+overlap] == e.Text[:overlap] {
					if e.Span.EndByte > p.Span.EndByte {
						p.Text += e.Text[overlap:]
						originals[j] += original[i].Text[overlap:]
						p.Span.EndByte = e.Span.EndByte
						p.Span.EndLine = e.Span.EndLine
					}
					refs[i] = j
					matched = true
				}
			}
		}
		if !matched {
			e.Kind = "source_excerpt"
			refs[i] = len(excerpts)
			excerpts = append(excerpts, e)
			originals = append(originals, original[i].Text)
		}
	}
	out := make([]wireEvidence, len(table))
	for i, e := range table {
		out[i].Evidence = e
		if j, ok := refs[i]; ok {
			out[i].Text = ""
			out[i].TextRef = fmt.Sprintf("s%d", j)
			// Columns locate each node in the condensed excerpt, including distinct
			// same-kind calls on one line. First-line columns are excerpt-relative.
			excerpt := excerpts[j]
			start, end := e.Span.StartByte-excerpt.Span.StartByte, e.Span.EndByte-excerpt.Span.StartByte
			column := func(offset int) int {
				prefix := condenseMaskedSpaces(originals[j][:offset], excerpt.Text[:offset])
				_, line, found := strings.Cut(prefix, "\n")
				if found {
					line = prefix[strings.LastIndex(prefix, "\n")+1:]
				} else {
					line = prefix
				}
				return utf8.RuneCountInString(line) + 1
			}
			out[i].StartColumn, out[i].EndColumn = column(start), column(end)
		}
	}
	for i := range out {
		out[i].Text = condenseMaskedSpaces(original[i].Text, out[i].Text)
	}
	for i := range excerpts {
		excerpts[i].Text = condenseMaskedSpaces(originals[i], excerpts[i].Text)
	}
	return out, excerpts
}

// Condense only spaces proven to come from masking. Source whitespace, including
// whitespace inside multiline string literals, is otherwise byte-for-byte intact.
// Newlines are never removed, so original evidence line ranges still apply.
func condenseMaskedSpaces(original, masked string) string {
	if len(original) != len(masked) {
		return masked
	}
	var out strings.Builder
	for i := 0; i < len(masked); {
		if masked[i] != ' ' {
			out.WriteByte(masked[i])
			i++
			continue
		}
		j, changed := i, false
		for j < len(masked) && masked[j] == ' ' {
			changed = changed || original[j] != ' '
			j++
		}
		if changed {
			out.WriteByte(' ')
		} else {
			out.WriteString(masked[i:j])
		}
		i = j
	}
	return out.String()
}

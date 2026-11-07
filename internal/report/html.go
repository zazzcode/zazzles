package report

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

//go:embed report.html
var htmlSource string

//go:embed report-sort.js
var sortSource string

var htmlReport = template.Must(template.New("report").Funcs(template.FuncMap{
	"label": displayLabel,
}).Parse(htmlSource))

type htmlItem struct {
	Finding analysis.Finding
	Use     analysis.CandidateUse
}
type htmlRow struct {
	ID, SourceType, Signature   string
	Path, Method                string
	Location                    analysis.Span
	Details                     []entryDetail
	Locations                   []analysis.Evidence
	Items                       []htmlItem
	Types                       []htmlTypePill
	Gaps                        []analysis.Gap
	Findings, Review, Protected int
}
type htmlView struct {
	Discovery                   []analysis.DiscoveryProposal
	SortScript                  template.JS
	ScriptHash                  string
	Glossary                    []analysis.FindingType
	CheckMatches                []analysis.CheckMatch
	Root                        string
	Rows                        []*htmlRow
	ClientRows                  []*htmlRow
	Gaps                        []analysis.Gap
	Limitations                 []string
	Skipped                     []string
	EntryCount                  int
	Findings, Review, Protected int
}

// HTML renders a standalone snapshot with native disclosure rows and no network resources.
func HTML(w io.Writer, r *analysis.AnalysisReport) error {
	Enrich(r)
	v := htmlView{Discovery: r.Discovery, CheckMatches: r.CheckMatches, Glossary: r.FindingTypes, Root: r.Root, Gaps: r.Gaps, Limitations: r.Limitations, Skipped: r.SkippedFamilies}
	hash := sha256.Sum256([]byte(sortSource))
	v.ScriptHash = base64.StdEncoding.EncodeToString(hash[:])
	// Trust only the compiled-in script. Report/source values stay escaped in data attributes.
	v.SortScript = template.JS(sortSource)
	rows := map[string]*htmlRow{}
	for _, e := range r.Entries {
		view := entryDetails(r, e)
		row := &htmlRow{ID: e.ID, SourceType: e.Kind, Signature: view.Label, Path: view.Label, Location: e.Location.Span, Gaps: r.EntryGaps(e.ID), Details: view.Details, Locations: view.Locations}
		if e.Kind == "http" && e.HTTP != nil {
			row.SourceType = "HTTP route"
			row.Path = e.HTTP.Path
			row.Method = e.HTTP.Method
		}
		if e.Kind == "browser" {
			row.SourceType = "Browser entry"
		}
		rows[e.ID] = row
		v.Rows = append(v.Rows, row)
	}
	for i, u := range r.Uses {
		identity := u.EntryID

		row := rows[identity]
		if row == nil {
			row = &htmlRow{ID: u.EntryID, SourceType: "Unresolved entry", Signature: "Entry association unavailable: " + u.EntryID, Path: u.EntryID}
			rows[u.EntryID] = row
			v.Rows = append(v.Rows, row)
		}
		f := r.Findings[i]
		row.Items = append(row.Items, htmlItem{f, u})
		switch f.RecordType {
		case "finding":
			row.Findings++
			v.Findings++
		case "protection":
			row.Protected++
			v.Protected++
		default:
			row.Review++
			v.Review++
		}
	}
	for _, row := range v.Rows {
		// Within a route, show records in the same precedence as the table: Findings, Review, Protected.
		sort.SliceStable(row.Items, func(i, j int) bool { return itemRank(row.Items[i].Finding) < itemRank(row.Items[j].Finding) })
		row.Types = rowTypePills(row.Items)
	}
	sort.SliceStable(v.Rows, func(i, j int) bool {
		a, b := v.Rows[i], v.Rows[j]
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		if a.Review != b.Review {
			return a.Review > b.Review
		}
		if a.Protected != b.Protected {
			return a.Protected > b.Protected
		}
		if (a.Path == "") != (b.Path == "") {
			return a.Path != ""
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.ID < b.ID
	})
	v.EntryCount = len(v.Rows)
	serverRows := make([]*htmlRow, 0, len(v.Rows))
	for _, row := range v.Rows {
		if strings.HasPrefix(row.SourceType, "Browser ") {
			v.ClientRows = append(v.ClientRows, row)
		} else {
			serverRows = append(serverRows, row)
		}
	}
	v.Rows = serverRows
	return htmlReport.Execute(w, v)
}
func displayLabel(value string) string {
	switch value {
	case "confirmed_vulnerability":
		return "Confirmed vulnerability · static analysis"
	case "poor_practice":
		return "Poor practice · remediate"
	case "observed_pattern":
		return "Legacy observation · review evidence"
	case "supported_potential":
		return "Potential vulnerability · review"
	case "needs_review":
		return "Analysis needs review"
	case "protected_for_claim":
		return "Protection supported for this claim"
	case "not_applicable":
		return "Not applicable to this claim"
	case "unknown", "uncertain", "needs_evidence":
		return "Inconclusive"
	case "not_run", "":
		return "Not assessed"
	case "completed":
		return "Assessment completed"
	case "failed":
		return "Assessment failed"
	}
	return value
}

// itemRank orders a route's records: established vulnerabilities, other findings, Review, Protected.
func itemRank(f analysis.Finding) int {
	switch {
	case f.RecordType == "finding" && f.Status == "confirmed_vulnerability":
		return 0
	case f.RecordType == "finding":
		return 1
	case f.RecordType == "protection":
		return 3
	default:
		return 2
	}
}

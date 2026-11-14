package report

import (
	"sort"
)

type htmlTypePill struct {
	ID, Label, Status, Tone                                      string
	Count, PoorPractice, Review, Potential, Protected, Confirmed int
}

func rowTypePills(items []htmlItem) []htmlTypePill {
	indexes := map[string]int{}
	pills := []htmlTypePill{}
	for _, item := range items {
		for _, id := range item.Finding.TypeIDs {
			i, ok := indexes[id]
			if !ok {
				i = len(pills)
				indexes[id] = i
				pills = append(pills, htmlTypePill{ID: id, Label: findingTypesByID[id].Label})
			}
			p := &pills[i]
			p.Count++
			status := item.Finding.Status
			if id == "input-validation" {
				status = "needs_evidence"
				c, a := item.Use.Completeness, item.Use.Assessment
				if c != nil && c.ClaimKind == "validation" && a.Status == "completed" && a.Answers["validation"] == "sufficient" && len(a.BlockingGaps) == 0 && item.Finding.Status == "protected_for_claim" {
					status = "protected_for_claim"
				} else if c != nil && c.ClaimKind == "validation" && a.Status == "completed" && a.Answers["validation"] == "insufficient" && len(a.BlockingGaps) == 0 && item.Finding.Status == "poor_practice" {
					status = "poor_practice"
				}
			}
			switch status {
			case "protected_for_claim":
				p.Protected++
			case "confirmed_vulnerability":
				switch id {
				case "sql-injection", "nosql-injection", "reflected-xss", "stored-xss", "dom-xss", "command-injection", "path-traversal", "sensitive-data-logging":
					p.Confirmed++
				default:
					p.Review++
				}
			case "poor_practice":
				p.PoorPractice++
			case "supported_potential":
				p.Potential++
			default:
				p.Review++
			}
		}
	}
	for i := range pills {
		p := &pills[i]
		switch {
		case p.Confirmed == p.Count:
			p.Status = "vulnerability"
			p.Tone = "confirmed-vulnerability"
		case p.Potential == p.Count:
			p.Status = "review"
			p.Tone = "review"
		case p.PoorPractice == p.Count:
			p.Status = "poor practice"
			p.Tone = "poor-practice"
		case p.Protected == p.Count:
			p.Status = "protected"
			p.Tone = "protected"
		case p.Review == p.Count:
			p.Status = "review"
			p.Tone = "review"
		default:
			p.Status = "mixed status"
			p.Tone = "review"
		}
	}
	sort.Slice(pills, func(i, j int) bool { return pills[i].Label < pills[j].Label })
	return pills
}

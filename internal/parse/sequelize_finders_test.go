package parse

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

const finderModel = `import { Model, DataTypes } from 'sequelize';
class Product extends Model {}
export { Product as ProductModel };
`

func sqlUses(t *testing.T, files map[string]string) []analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		writeSource(t, root, name, src)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			out = append(out, u)
		}
	}
	return out
}

// A call that only contains a nested function with an Op.like finder is not a
// SQL candidate; the finder itself is.
func TestSequelizeFinderDetection(t *testing.T) {
	server := `import express from 'express';import { Op } from 'sequelize';import { ProductModel } from './product';const app=express();
app.get('/search',(req,res)=>{const tools={search: tool({description:'x', execute: async ({ q }) => ProductModel.findAll({ where: { name: { [Op.like]: '%'+req.query.q+'%' } } })})};res.json(tools)});
function tool(spec){ return spec }`
	uses := sqlUses(t, map[string]string{"product.ts": finderModel, "server.ts": server})
	if len(uses) != 1 {
		t.Fatalf("sql candidates=%d: %+v", len(uses), uses)
	}
	if text := uses[0].Sink.Text; len(text) < 20 || text[:20] != "ProductModel.findAll" {
		t.Fatalf("candidate is not the finder: %s", text)
	}
}

func TestSequelizeFinderContract(t *testing.T) {
	for _, tt := range []struct {
		name, model, call, want string
	}{
		{"verified model", finderModel, `ProductModel.findAll({ where: { name: { [Op.like]: '%'+req.query.q+'%' } } })`, "sequelize-model-finder-v1"},
		{"findOne template", finderModel, "ProductModel.findOne({ where: { name: { [Op.like]: `%${req.query.q}%` } } })", "sequelize-model-finder-v1"},
		{"unverified receiver", `export const ProductModel = { findAll(x){ return x } };`, `ProductModel.findAll({ where: { name: { [Op.like]: '%'+req.query.q+'%' } } })`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := `import express from 'express';import { Op } from 'sequelize';import { ProductModel } from './product';const app=express();
app.get('/search',(req,res)=>{` + tt.call + `;res.send('ok')});`
			uses := sqlUses(t, map[string]string{"product.ts": tt.model, "server.ts": server})
			if len(uses) != 1 {
				t.Fatalf("sql candidates=%d", len(uses))
			}
			u := uses[0]
			got := ""
			if u.APIModel != nil {
				got = u.APIModel.ID
			}
			if got != tt.want {
				t.Fatalf("contract=%q want %q", got, tt.want)
			}
			if tt.want == "" {
				return
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("selection: %+v", u.Components)
			}
			like := false
			for _, g := range u.Completeness.Coverage {
				like = like || g.Kind == "like_pattern_interpolated"
			}
			for _, g := range u.Completeness.Blockers {
				if g.Kind == "like_pattern_interpolated" || g.Kind == "query_text_interpolated" {
					t.Fatalf("LIKE pattern recorded as a blocker or as executable SQL text: %+v", g)
				}
			}
			if !like {
				t.Fatal("LIKE wildcard gap missing")
			}
		})
	}
}

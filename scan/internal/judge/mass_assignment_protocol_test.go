package judge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

const ownerFixture = `const express = require('express')
const crypto = require('crypto')
const { Model, DataTypes } = require('sequelize')
class Captain extends Model {}
Captain.init({ handle: DataTypes.STRING, passcode: { type: DataTypes.STRING, set (clear) { this.setDataValue('passcode', crypto.createHash('md5').update(clear).digest('hex')) } } }, { sequelize })
class Ship extends Model {}
Ship.init({ name: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Ship.belongsTo(Captain)
class Chart extends Model {}
Chart.init({ title: DataTypes.STRING, userId: DataTypes.INTEGER }, { sequelize })
const app = express()
app.post('/ships', async (req, res) => { await Ship.create(req.body); res.send('ok') })
app.post('/charts', async (req, res) => { await Chart.create(req.body); res.send('ok') })
`

func massUseFor(t *testing.T, route string) analysis.CandidateUse {
	t.Helper()
	r, err := pipeline.Analyze(writeFixture(t, map[string]string{"server.js": ownerFixture}), "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, e := range r.Entries {
		names[e.ID] = e.Name
	}
	for _, u := range r.Uses {
		if u.Kind == analysis.MassAssignmentKind && names[u.EntryID] == route {
			return u
		}
	}
	t.Fatalf("no mass-assignment record for %s", route)
	return analysis.CandidateUse{}
}

func fieldImpact(t *testing.T, request []byte) string {
	t.Helper()
	var body struct {
		Questions []struct {
			Name         string `json:"name"`
			Instructions string `json:"instructions"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(request, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Questions) != 3 {
		t.Fatalf("%d questions", len(body.Questions))
	}
	for _, q := range body.Questions {
		if q.Name == "field_impact" {
			return q.Instructions
		}
	}
	t.Fatal("no field_impact question")
	return ""
}

// TestMassAssignmentProtocol covers S-4: v2 only for a record that carries an
// owner_reference field; every other record keeps the v1 questions and
// protocol; the policy accepts both.
func TestMassAssignmentProtocol(t *testing.T) {
	v1 := analysispacks.MassAssignmentQuestions()[2].Instructions
	v2 := analysispacks.MassAssignmentQuestionsV2()[2].Instructions
	if v1 == v2 || !strings.HasPrefix(v2, v1) || !strings.Contains(v2, "An owner_reference field is the foreign key of a declared association to the account model, from the association contract; a request that chooses it chooses whose record is written.") {
		t.Fatalf("v2 text %q", v2)
	}
	c, _ := New("openai", "fixture-model", "never-persist-key")
	for _, tt := range []struct {
		route, protocol, text string
		role                  bool
	}{
		{"POST /ships", analysispacks.MassAssignmentProtocolV2, v2, true},
		{"POST /charts", analysispacks.MassAssignmentProtocol, v1, false},
	} {
		t.Run(tt.route, func(t *testing.T) {
			u := massUseFor(t, tt.route)
			if got := analysispacks.MassAssignmentOwnerReference(u); got != tt.role {
				t.Fatalf("owner_reference role %v, want %v", got, tt.role)
			}
			if protocolVersion(u) != tt.protocol {
				t.Fatalf("protocol %q, want %q", protocolVersion(u), tt.protocol)
			}
			trace, err := c.Preview(u)
			if err != nil {
				t.Fatal(err)
			}
			if trace.QuestionVersion != tt.protocol {
				t.Fatalf("trace version %q", trace.QuestionVersion)
			}
			if got := fieldImpact(t, trace.Request); got != tt.text {
				t.Fatalf("field_impact %q, want %q", got, tt.text)
			}
			if !tt.role && strings.Contains(string(trace.Request), "owner_reference field is the foreign key") {
				t.Fatal("v1 request carries the v2 sentence")
			}
			// The fallback question list and the selected material agree.
			for _, q := range questionsFor(u) {
				if q.name == "field_impact" && q.instructions != tt.text {
					t.Fatalf("questionsFor field_impact %q", q.instructions)
				}
			}
			a := analysis.Assessment{QuestionVersion: tt.protocol, Answers: map[string]string{"key_control": "request_chosen", "key_restriction": "none", "field_impact": "privileged_field"}}
			applyPolicy(u, &a)
			for _, g := range a.BlockingGaps {
				if g.Kind == "mass_assignment_protocol_missing" {
					t.Fatalf("policy refuses protocol %s", tt.protocol)
				}
			}
		})
	}
}

package langjs

import "testing"

// TestGSSPInputOrderDeterministic keeps getServerSideProps context inputs in
// pattern source order. Map iteration once reordered them between runs, which
// changed the invocation and candidate IDs (found by phase 5's corpus diff).
func TestGSSPInputOrderDeterministic(t *testing.T) {
	root := nextRepo(t, map[string]string{"pages/p.js": `export default function P({ data }) { return <p>{data}</p>; }
export async function getServerSideProps({ req, query }) {
  const r = await fetch(new URL(String(query.u), 'http://' + req.headers.host));
  return { props: { data: await r.text() } };
}`})
	for i := 0; i < 40; i++ {
		r := analyzeNext(t, root)
		got := ""
		for _, c := range r.InvocationContexts {
			for _, in := range c.Inputs {
				got += in.Parameter + ","
			}
		}
		if got != "req,query," {
			t.Fatalf("run %d: invocation inputs %q, want req,query in source order", i, got)
		}
	}
}

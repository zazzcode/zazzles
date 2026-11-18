package parse

import "testing"

// Return parameters over-approximate reads: every parameter a closed summary
// returns is one it read. The Python and PHP closed-summary tests live in
// internal/langpy and internal/langphp.
func TestClosedCallableReturnsAreReads(t *testing.T) {
	c := &ClosedCallable{Params: []string{"a", "b", "c"}}
	c.Read("a", "f.py", nil)
	c.Read("c", "f.py", nil)
	c.Finish()
	if !c.Closed() {
		t.Fatalf("closed=%v reasons=%v", c.Closed(), c.Reasons)
	}
	if c.returns&^c.reads != 0 || c.reads != 0b101 {
		t.Fatalf("reads=%b returns=%b", c.reads, c.returns)
	}
}

package analysis

// PollutionKind is the write claim for Object.prototype (CWE-1321).
const PollutionKind = "prototype_write_candidate"

const (
	PollutionFinding = "prototype-pollution"
	PollutionMerge   = "recursive_merge"
	PollutionWalk    = "path_walk"
	PollutionNested  = "nested_write"
)

// PollutionFacts records the key-bearing operand and source-backed controls for a write.
type PollutionFacts struct {
	Operation  string        `json:"operation"`
	ContractID string        `json:"contract_id,omitempty"`
	Package    string        `json:"package,omitempty"`
	Version    string        `json:"version,omitempty"`
	KeyOperand string        `json:"key_operand"`
	KeyLevels  int           `json:"key_levels,omitempty"`
	Guard      string        `json:"guard,omitempty"`
	Blocked    []string      `json:"blocked,omitempty"`
	Open       []string      `json:"open,omitempty"`
	Paths      []CommandPath `json:"paths"`
}

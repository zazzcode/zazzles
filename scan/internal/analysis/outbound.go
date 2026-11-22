package analysis

import "fmt"

// Destination origins of an outbound call's destination operand. They describe
// what the bounded flow established for that slot only, never request bodies.
const (
	// DestinationRequest: a request input reaches the destination operand.
	DestinationRequest = "request"
	// DestinationExternalData: only stored or remote-response data reaches it.
	DestinationExternalData = "external_data"
	// DestinationConstant: a string literal or a template with no substitution.
	DestinationConstant = "constant"
	// DestinationEnvironment: an unshadowed environment read, directly or through
	// one local value or parameter default.
	DestinationEnvironment = "environment"
	// DestinationUnestablished: none of the above was established; not a verdict.
	DestinationUnestablished = "unestablished"
)

// OutboundSlotDestination labels dependencies that reach the destination operand.
const OutboundSlotDestination = "destination"

// OutboundFacts records an outbound HTTP call's verified operation and the
// origin of its destination operand. Paths are present only for a request-
// derived destination; each is one source-to-destination path with its own
// controls (use.Context indices) and never a global safe bit.
type OutboundFacts struct {
	Operation         string `json:"operation,omitempty"`
	ContractID        string `json:"contract_id,omitempty"`
	DestinationOrigin string `json:"destination_origin"`
	// Transport is shell_client when the destination is a curl or wget
	// argument. Empty for every earlier contract, so those records stay put.
	Transport string `json:"transport,omitempty"`
	// Operand is proxy or url when the shell token is a proxy or --url value.
	Operand string        `json:"operand,omitempty"`
	Paths   []CommandPath `json:"paths,omitempty"`
}

// Validate checks every path index and enumerated value against the use.
func (o *OutboundFacts) Validate(deps, context int) error {
	if o == nil {
		return nil
	}
	switch o.DestinationOrigin {
	case DestinationRequest, DestinationExternalData, DestinationConstant, DestinationEnvironment, DestinationUnestablished:
	default:
		return fmt.Errorf("invalid destination origin %q", o.DestinationOrigin)
	}
	for _, p := range o.Paths {
		if p.Dependency < 0 || p.Dependency >= deps || p.Operand != OutboundSlotDestination {
			return fmt.Errorf("outbound path references a missing dependency or slot")
		}
		switch p.Protection {
		case "raw", "guarded", "unknown":
		default:
			return fmt.Errorf("invalid outbound path protection %q", p.Protection)
		}
		for _, i := range p.Controls {
			if i < 0 || i >= context {
				return fmt.Errorf("outbound path control %d out of range", i)
			}
		}
	}
	return nil
}

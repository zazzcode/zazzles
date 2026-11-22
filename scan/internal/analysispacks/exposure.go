package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// ExposureProtocol versions the information-exposure claim questions.
const ExposureProtocol = "exposure-components-v1"

// PHPDiagnosticOutput identifies the PHP diagnostic-output operations of
// branch 1 D-1.
const PHPDiagnosticOutput = "php-diagnostic-output-v1"

var exposureContracts = []string{PHPDiagnosticOutput}

// ExposureRoles are the evidence obligations of the operation-centered claim.
// The claim has no request source (lane contract section 2.7).
func ExposureRoles() []string {
	return []string{"diagnostic_operation", "entry", "control_flow"}
}

// ExposureContract returns the semantics of the verified diagnostic operations.
func ExposureContract(id string) *analysis.APIModel {
	if id != PHPDiagnosticOutput {
		return nil
	}
	return &analysis.APIModel{ID: id, Library: "php", Reference: "https://www.php.net/manual/en/function.phpinfo.php",
		Semantics: "phpinfo() outputs the PHP configuration, loaded modules, environment variables, server variables and request headers; an INFO_* flag selects sections. debug_print_backtrace() prints the call stack with arguments. var_dump, var_export and print_r (not returning) print their argument: over $_SERVER, $_ENV, $GLOBALS, getenv(), get_defined_vars(), ini_get_all() or get_defined_constants() that is environment, configuration or runtime state. getenv() with no argument, php_uname(), phpversion() and ini_get_all() return server state that an echo, print, Response body or template output then discloses. Symfony dump() and dd() print their arguments only when the debug component is active, so their output depends on the environment. Dumping an ordinary local value is not this claim."}
}

func exposureQuestionNames() []string {
	return []string{"exposure_output", "exposure_reach"}
}

// ExposureQuestions returns the family's questions in protocol order (D-13).
func ExposureQuestions() []Question {
	return []Question{
		{"exposure_output", "Does the recorded operation emit server configuration, environment, runtime state or a stack, as use.exposure.subject states (internal_state, benign, unknown)? Judge the recorded operation and its operand, not the surrounding page."},
		{"exposure_reach", "Can a caller reach the operation through the recorded entry, given use.exposure.guards and use.exposure.entry_served (reachable, restricted, unknown)? A guard restricts reach only when it dominates the operation and rejects the caller; answer restricted only for a recorded guard."},
	}
}

// ExposureChoices lists the accepted answers for an exposure question.
func ExposureChoices(question string) []map[string]string {
	switch question {
	case "exposure_output":
		return choicePairs(
			[2]string{"internal_state", "The operation emits server configuration, environment, runtime state or a stack."},
			[2]string{"benign", "The operation emits nothing internal for this claim."},
			[2]string{"unknown", "The supplied evidence does not establish what the operation emits."},
		)
	case "exposure_reach":
		return choicePairs(
			[2]string{"reachable", "A caller of the recorded entry reaches the operation with no restricting guard."},
			[2]string{"restricted", "A recorded guard that dominates the operation restricts who reaches it."},
			[2]string{"unknown", "Reach cannot be established from the supplied entry and guards."},
		)
	}
	return nil
}

func choicePairs(pairs ...[2]string) []map[string]string {
	out := make([]map[string]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, map[string]string{"value": pair[0], "description": pair[1]})
	}
	return out
}

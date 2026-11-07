package analysispacks

import "github.com/zazzcode/zazzles/internal/analysis"

// CommandProtocol is the command-execution question/envelope protocol.
const CommandProtocol = "command-components-v1"

// Operation-contract identifiers. Each is selected only after the parser
// verified the actual import/require binding of the called process API.
const (
	NodeShellContract  = "node-child-process-shell-v1"
	NodeArgvContract   = "node-child-process-argv-v1"
	PythonOSContract   = "python-os-shell-v1"
	PythonSubprocessID = "python-subprocess-v1"
)

var commandContractIDs = []string{NodeShellContract, NodeArgvContract, PythonOSContract, PythonSubprocessID}

// CommandContract returns a copy of the supported operation contract by verified ID.
// Semantics follow the cited official documentation reviewed 2026-11-07; the
// scanner host and moving documentation versions are not evidence of the target runtime.
func CommandContract(id string) *analysis.APIModel {
	switch id {
	case NodeShellContract:
		return &analysis.APIModel{ID: id, Library: "child_process", Reference: "https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback",
			Semantics: "exec and execSync run their first argument as shell command text (POSIX /bin/sh unless options.shell names another interpreter). Request text in that operand can add commands, substitutions, redirection and separators. A custom shell option selects the interpreter; a non-string or invalid shell value does not turn this into a safe argument-array API. options.cwd, env, timeout and the callback output parameters are not command text. This contract is not evidence of the deployed platform."}
	case NodeArgvContract:
		return &analysis.APIModel{ID: id, Library: "child_process", Reference: "https://nodejs.org/api/child_process.html#child_processspawncommand-args-options",
			Semantics: "execFile, execFileSync, spawn and spawnSync take an executable and an array of separate arguments; with options.shell absent or false no shell parses them, so arguments are data to that program but may still be options. With options.shell true or a shell path the command and arguments are joined into shell text and are not separated data. A literal sh/bash executable with -c still has a shell command operand even with shell disabled. A request value in the executable position selects the program. Omitted args and callback overloads shift operand positions; options.cwd and env are separate configuration, not command text."}
	case PythonOSContract:
		return &analysis.APIModel{ID: id, Library: "os", Reference: "https://docs.python.org/3/library/os.html#os.system",
			Semantics: "os.system and os.popen pass their string argument to the platform shell (POSIX sh -c). Request text in that operand can add commands, substitutions, redirection and separators. os.popen's mode argument and the returned file object handle output only; they are not command text."}
	case PythonSubprocessID:
		return &analysis.APIModel{ID: id, Library: "subprocess", Reference: "https://docs.python.org/3/library/subprocess.html#popen-constructor",
			Semantics: "subprocess.run, Popen, call, check_call and check_output default to shell=False. With shell=False a sequence is an executable plus separate arguments, and a string is the program name, not shell text. On POSIX with shell=True a string is shell command text; for a sequence the first item is shell command text and the remaining items are arguments to the shell itself, not concatenated into that command. The executable keyword replaces the shell or program. stdin/stdout/stderr/timeout/input are not command text; cwd and env are separate configuration. A literal sh/bash with -c is an interpreter command operand even when shell=False."}
	}
	return nil
}

func commandQuestionNames() []string {
	var names []string
	for _, q := range CommandQuestions() {
		names = append(names, q.Name)
	}
	return names
}

// CommandQuestions returns the exact ordered command claim protocol. Shell
// syntax, executable choice, argument interpretation and coverage are separate facets.
func CommandQuestions() []Question {
	return []Question{
		{"shell_syntax_protection", "Can supported external text alter the effective shell syntax of this process use? vulnerable requires a verified binding, a request-derived value in an effective shell command operand (exec/execSync/os.system/os.popen text, subprocess shell=True command text, or the command operand of a literal sh/bash -c) and no enforced constraint on that supported path. protected requires an enforced source-backed constraint (for example a finite allow-list of literals that cannot contain shell syntax with a rejecting branch that terminates before use) on every relevant path; casts, annotations, length limits, blacklist replacement, exception handling and unrelated hashing are not protection, and general quoting is not established. not_applicable means the effective shell mode is disabled with data operands only and no literal interpreter command. unknown covers missing bindings, options, operands or path facts. Answering vulnerable for a verified shell-disabled data operand is contradictory. Judge each request-derived path separately: one supported unguarded path to a shell command operand is vulnerable even if another path to the same operand is unresolved."},
		{"executable_control", "Is the executable or interpreter selection fixed or source-constrained? unsafe means a request-derived value selects the executable, the executable override or the shell configuration on a supported path. constrained requires a fixed executable (an absolute path avoids PATH resolution) or an enforced source-backed finite choice. not_applicable means the executable is selected by a shell command string covered by the shell facet. unknown covers a bare program name whose PATH selection is unresolved, dynamic options and missing facts. A fixed executable does not protect its arguments."},
		{"argument_control", "Do the supplied semantics establish dangerous option/interpreter control through argument operands, or enforced data-only constraints? unsafe requires a verified separate-argument operand whose request value can supply an option or interpreter semantics that the supplied evidence establishes for that executable, never a guess about an unknown utility. constrained requires an enforced source-backed constraint such as finite permitted literals that cannot be option syntax, with the rejecting branch terminating before use. not_applicable means no separate argument operand is request-derived. unknown covers unknown utility options, unmodeled argv shape and missing guard facts; unknown utility options are Review, not a positive."},
		{"protection_coverage", "Are the relevant operand and path protection obligations established? complete requires every relevant request-derived operand and every feasible source-to-operand path to be covered by the answers above with no unknown relevant helper, mutable operand, dispatch or guard. incomplete means a supported unsafe or unprotected sibling path, operand or invocation remains. unknown means coverage cannot be determined. A constraint on one operand, branch or invocation does not cover another; an all-not_applicable result is not protection. A request-derived path that is raw in the supplied path facts is an unsafe witness even when a sibling path is unresolved; answer unknown for a facet only when no supported path establishes it."},
	}
}

// CommandChoices returns the choices of one command question.
func CommandChoices(name string) []map[string]string {
	var values [][2]string
	switch name {
	case "shell_syntax_protection":
		values = [][2]string{{"vulnerable", "The supplied source and verified contract establish request text altering effective shell syntax on a supported path."}, {"protected", "An enforced source-backed constraint keeps request text from altering shell syntax on every relevant path."}, {"not_applicable", "The effective shell mode is disabled with data operands only; no shell command operand exists."}, {"unknown", "Required binding, option, operand or path evidence is missing or ambiguous."}}
	case "executable_control":
		values = [][2]string{{"unsafe", "A request-derived value selects the executable, interpreter, override or shell configuration."}, {"constrained", "The executable is fixed or an enforced source-backed finite choice."}, {"not_applicable", "No separate executable operand applies to this use."}, {"unknown", "Executable selection or its PATH resolution is not established."}}
	case "argument_control":
		values = [][2]string{{"unsafe", "A request-derived argument operand has established option or interpreter control."}, {"constrained", "Argument operands are enforced, source-backed data-only constraints."}, {"not_applicable", "No request-derived separate argument operand applies."}, {"unknown", "Argument semantics, utility options or constraints are not established."}}
	case "protection_coverage":
		values = [][2]string{{"complete", "Relevant operand and path protection obligations are established."}, {"incomplete", "A relevant operand, path or sibling remains unprotected or unanalyzed."}, {"unknown", "Coverage cannot be determined from the supplied evidence."}}
	default:
		return nil
	}
	out := make([]map[string]string, 0, len(values))
	for _, v := range values {
		out = append(out, map[string]string{"value": v[0], "description": v[1]})
	}
	return out
}

var commandOwners = map[string]string{
	NodeShellContract:  "internal/parse/command_node.go",
	NodeArgvContract:   "internal/parse/command_node.go",
	PythonOSContract:   "internal/parse/python_command.go",
	PythonSubprocessID: "internal/parse/python_command.go",
}

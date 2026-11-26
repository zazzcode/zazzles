package analysispacks

// SQLTextContract marks a sql_query_candidate record made from SQL statement
// text found in a call argument, with no driver contract. It names no driver,
// method or package. The record's slots are SQLTextSlot (the argument that holds
// the statement text) and SQLTextParametersSlot (the other arguments).
const SQLTextContract = "sql-text-v1"

// SQLTextLibrary is the library of SQLTextContract. It is not a package name.
const SQLTextLibrary = "sql-text"

// SQLTextSemantics is the contract's one neutral sentence.
const SQLTextSemantics = "SQL statement text recognized in an argument; no driver contract."

// SQLTextOperationProtocol is the question protocol of a record whose contract is
// SQLTextContract. It is selected by the record's contract, never for the SQL
// family as a whole.
const SQLTextOperationProtocol = "sql-text-operation-v1"

// SQLTextOperationQuestions asks what the call does with SQL text and whether an
// input exists that changes the statement beyond the choices the code lists.
func SQLTextOperationQuestions() []Question {
	return []Question{
		{"operation", "What does the call do with SQL text? Decide from the call and source."},
		{"request_control", "Is there an input an attacker can send that changes the SQL statement beyond the choices the code itself lists? Work it out concretely: take each request value from where it is read, apply every conversion, check and helper in source in order, and see where it arrives: inside the statement text, or apart from it as a bound value. Selecting one of several alternatives that the code lists (a key of a constant map, a member of a constant list) is not such an input; neither is a value that arrives as a bound value, as a number, or inside a quoted literal with every character that could end the literal escaped for that database. A check counts only when it runs before the call and stops the request, by returning or throwing, for every value it does not allow; a check on another value, or a fallback that keeps the original value, protects nothing. One such input on one path is enough."},
	}
}

// SQLTextOperationChoices returns the closed answers of an SQL text operation question.
func SQLTextOperationChoices(name string) []map[string]string {
	switch name {
	case "operation":
		return []map[string]string{
			{"value": "runs_sql", "description": "The call sends SQL statement text to a database to be run or prepared, or runs a statement that was prepared from such text."},
			{"value": "not_database_operation", "description": "The call does not send SQL to a database: it logs, prints, returns, stores or compares the text, or builds a value."},
			{"value": "cannot_tell", "description": "The supplied source does not show what the call is."},
		}
	case "request_control":
		return []map[string]string{
			{"value": "statement_text", "description": "Yes: text the attacker writes arrives inside the statement text, placed there by concatenation, interpolation, formatting or replacement, outside a quoted literal or without escaping that fits the database and the quoting."},
			{"value": "name", "description": "Yes: a table or column name, an ordering or a keyword that the code does not list arrives in the statement text."},
			{"value": "data_only", "description": "No: on every path each request value arrives only as a bound value passed apart from the statement text, a number, a fully escaped quoted literal, or one of the alternatives the code lists."},
			{"value": "cannot_tell", "description": "The supplied source does not show what a check, conversion or helper on the way does, or where the statement text comes from."},
		}
	}
	return nil
}

// SQLTextOperationControls are the request_control answers that are a finding.
var SQLTextOperationControls = map[string]bool{"statement_text": true, "name": true}

// SQLTextLanguage is the query_language note of an SQL text request.
const SQLTextLanguage = "SQL: the database parses the whole statement text. Request text placed into the statement text by concatenation, interpolation, formatting or replacement becomes part of the statement, and can end a quoted literal or add clauses and statements. A value passed apart from the statement text, for a placeholder (?, $1, :name, @name, or %s with a separate parameter argument) or through a bind call on a prepared statement, is data and cannot change the statement. A placeholder protects only the value bound to it, not text already put into the statement. A table or column name, a keyword such as ASC, and a row count cannot be bound; they are safe only when the code picks them from a list it holds or converts them to a number. An escaping function protects only inside a quoted literal of the database it belongs to."

// Slot names of a SQL text record's dependencies.
const (
	SQLTextSlot           = "sql_text"
	SQLTextParametersSlot = "sql_parameters"
)

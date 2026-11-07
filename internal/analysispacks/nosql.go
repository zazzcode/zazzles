package analysispacks

import "github.com/zazzcode/zazzles/internal/analysis"

// noSQLContractIDs lists the verified NoSQL operation contracts. MarsDB has
// Mongo-style matching semantics; this does not make it a MongoDB server or
// establish support for any MongoDB driver. Python NoSQL stays unimplemented.
var noSQLContractIDs = []string{"marsdb-collection-v1", "mongoose-model-query-v1", "mongoose-model-query-v2", "mongoose-path-id-objectid-v1", "mongoose-find-by-id-objectid-v1"}

// NoSQLContract returns a copy of the supported operation contract by verified
// model ID. It applies only after parse proved the collection/model binding.
func NoSQLContract(id string) *analysis.APIModel {
	switch id {
	case "mongoose-find-by-id-objectid-v1":
		return &analysis.APIModel{ID: id, Library: "mongoose", Reference: "https://github.com/Automattic/mongoose/blob/4.2.4/lib/model.js#L1179", Semantics: "The selected manifest pins Mongoose 4.2.4 and the verified literal schema retains its default ObjectId _id. findById(id) is findOne({_id:id}); the query caster casts the operand under ObjectId semantics. Primitive strings are cast to ObjectId or raise CastError, without JSON parsing string contents into selector operators. Object-valued operands can carry recognized query operators and do not inherit scalar protection. Determine the actual operand type and constraints from the separate source/transfer/hook facts, regardless of HTTP, RPC or other input acquisition. Source-present validation can be assessed semantically; missing implementations remain blockers. Custom ID types/hooks, authorization, ownership, valid-ID error handling and stored rendering are separate concerns. Installed runtime is not verified."}
	case "mongoose-path-id-objectid-v1":
		return &analysis.APIModel{ID: id, Library: "mongoose", Reference: "https://github.com/Automattic/mongoose/blob/4.2.4/lib/model.js#L1179", Semantics: "The selected manifest pins Mongoose 4.2.4; installed runtime is not verified. This operation is findById(id), implemented as findOne({_id:id}), with the verified model's default ObjectId _id and no unresolved custom schema behavior. Its ObjectId query caster converts the primitive string to an ObjectId or throws a CastError; it does not JSON-parse string contents into selector operators (lib/schema/objectid.js, cast and castForQuery). The accompanying selector_path_string evidence identifies a direct, unmodified Express named URL parameter. Express's route matcher supplies that parameter as a decoded primitive string, not a parsed body/query object. JSON-looking text or $ne in that string cannot introduce query operators. For this exact input and operation, syntax/operator protection can be established without an application validator; externally controlled source coverage remains yes even though the value cannot control operators. Invalid IDs/error handling, business validation, authorization and stored-content rendering are separate claims. These facts must not be applied to body/query objects, modified parameters, custom _id schemas, unknown hooks or other operations."}
	case "marsdb-collection-v1":
		return &analysis.APIModel{ID: "marsdb-collection-v1", Library: "marsdb", Semantics: "MarsDB Collection uses Mongo-style selector matching. $where string values are executable JavaScript predicates, not bound data. A request object in a selector field can introduce matching operators such as $ne. Ordinary scalar values in document data slots are not executable expressions. Review each selector versus update-value slot and constraints separately.", Reference: "https://github.com/c58/marsdb/blob/master/lib/DocumentMatcher.js"}
	case "mongoose-model-query-v1":
		return &analysis.APIModel{ID: "mongoose-model-query-v1", Library: "mongoose", Semantics: "Mongoose model selectors depend on schema casting, scalar constraints and permitted query operators. Input objects can carry selectors; findById has ObjectId casting semantics. A model binding alone does not establish injection or protection. Inspect the actual operation, schema/version and input constraints.", Reference: "https://mongoosejs.com/docs/tutorials/query_casting.html"}
	case "mongoose-model-query-v2":
		return &analysis.APIModel{ID: "mongoose-model-query-v2", Library: "mongoose", Reference: "https://github.com/Automattic/mongoose/blob/4.2.4/lib/cast.js", Semantics: "The selected-root manifest pins Mongoose4.2.4; installed runtime is not verified. Its query caster retains recognized $ operators in filter objects and casts their operands. SchemaString inherits $ne/$eq/$in/$nin conditional handlers, so a String schema path does not itself reject an operator object or force scalar equality. Persistence validation and schema types do not sanitize query filters. Inspect the actual schema, operation/slot and application guards; scalar guards, custom setters/hooks, casts and findById ObjectId behavior must not inherit a different field's conclusions."}
	}
	return nil
}

func noSQLQuestionNames() []string {
	out := []string{"validation", "protection", "injection_protection"}
	return append(out, "all_paths_protected", "source_coverage", "library_coverage", "guard_coverage", "path_coverage")
}

// NoSQLQuestions returns the NoSQL claim: shared validation/construction
// facets, selector-operator injection and the all-path/coverage protocol.
func NoSQLQuestions() []Question {
	out := BaseQuestions()
	out = append(out, Question{"injection_protection", InjectionInstructions})
	return append(out,
		Question{"all_paths_protected", "Does positive evidence establish injection protection on ALL relevant feasible branches? yes=every source-to-operation alternative has adequate syntax/operator protection; no=at least one supported branch leaves attacker syntax/operator control; unknown=an alternative's protection cannot be decided. A numeric guarantee applies only to that conversion's output, never automatically to sibling branches. Business/format validation is separate."},
		Question{"source_coverage", "For the injection question, is a relevant externally controlled source and its transfer into the actual selector/expression slot established? yes=the request source and transfer are established; no=positive evidence the relevant slot is not externally controlled; unknown=source or transfer facts are missing."},
		Question{"library_coverage", "For the injection question, do the verified import/constructor evidence and supplied API contract establish the actual collection and selector/expression behavior? yes=the actual collection/API slot is identified with its contract; no=positive evidence this is a different API; unknown=library or slot semantics are missing."},
		Question{"guard_coverage", "For the injection question, are relevant middleware and value constraints described well enough to assess their effect? yes=relevant guard/check effects are available (including an absence of guards in the supplied complete slice); no=an applicable check body is missing; unknown=coverage is ambiguous. Effective and ineffective guards can both have adequate coverage."},
		Question{"path_coverage", "For the injection question, is at least one relevant path's feasibility established? yes=a relevant source-to-operation path is supported under stated possible conditions; no=the operation is proven unreachable for that input; unknown=necessary branch/callback/return facts are missing. A reported static path does not require executing the application."})
}

// NoSQLCoverageChoices returns the shared yes/no/unknown coverage protocol.
func NoSQLCoverageChoices() []map[string]string {
	return []map[string]string{
		{"value": "yes", "description": "The fact asked about by this question is established by the supplied evidence."},
		{"value": "no", "description": "The supplied evidence establishes the contrary fact or identifies the missing body, as defined in this question."},
		{"value": "unknown", "description": "The evidence does not establish the requested fact or its contrary."},
	}
}

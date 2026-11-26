package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// noSQLContractIDs lists the verified NoSQL operation contracts. MarsDB has
// Mongo-style matching semantics; this does not make it a MongoDB server or
// establish support for any MongoDB driver. Python NoSQL stays unimplemented.
var noSQLContractIDs = []string{"marsdb-collection-v1", "mongoose-model-query-v1", "mongoose-model-query-v2", "mongoose-path-id-objectid-v1", "mongoose-find-by-id-objectid-v1", PrismaFilterContract, MongoDBDocumentContract}

// PrismaFilterContract is Prisma Client's model filter (where) object.
const PrismaFilterContract = "prisma-filter-object-v1"

// MongoDBDocumentContract is the MongoDB document query language reached through
// the native driver (npm "mongodb"). It is selected by the package a call's
// receiver derives from, never by a method or variable name.
const MongoDBDocumentContract = "mongodb-document-query-v1"

// NoSQLContract returns a copy of the supported operation contract by verified
// model ID. It applies only after parse proved the collection/model binding.
func NoSQLContract(id string) *analysis.APIModel {
	switch id {
	case PrismaFilterContract:
		return &analysis.APIModel{ID: id, Library: "prisma", Reference: "https://www.prisma.io/docs/orm/reference/prisma-client-reference#filter-conditions-and-operators",
			Semantics: "Prisma Client model methods (findUnique, findFirst, findMany, count, update, updateMany, delete, deleteMany, upsert) compile a where object to parameterized SQL; values never change SQL syntax. A where field that receives an object instead of a scalar is read as a filter: { not: x }, { contains: '' }, { startsWith: '' }, { in: [...] }, { gt: '' } and similar operators widen or invert the match (operator injection; engine prisma). A runtime check that enforces a primitive type for that field (for example zod z.string()) prevents operator objects; TypeScript annotations do not. Mass assignment through data objects is a separate concern."}
	case "mongoose-find-by-id-objectid-v1":
		return &analysis.APIModel{ID: id, Library: "mongoose", Reference: "https://github.com/Automattic/mongoose/blob/4.2.4/lib/model.js#L1179", Semantics: "The selected manifest pins Mongoose 4.2.4 and the verified literal schema retains its default ObjectId _id. findById(id) is findOne({_id:id}); the query caster casts the operand under ObjectId semantics. Primitive strings are cast to ObjectId or raise CastError, without JSON parsing string contents into selector operators. Object-valued operands can carry recognized query operators and do not inherit scalar protection. Determine the actual operand type and constraints from the separate source/transfer/hook facts, regardless of HTTP, RPC or other input acquisition. Source-present validation can be assessed semantically; missing implementations remain blockers. Custom ID types/hooks, authorization, ownership, valid-ID error handling and stored rendering are separate concerns. Installed runtime is not verified."}
	case "mongoose-path-id-objectid-v1":
		return &analysis.APIModel{ID: id, Library: "mongoose", Reference: "https://github.com/Automattic/mongoose/blob/4.2.4/lib/model.js#L1179", Semantics: "The selected manifest pins Mongoose 4.2.4; installed runtime is not verified. This operation is findById(id), implemented as findOne({_id:id}), with the verified model's default ObjectId _id and no unresolved custom schema behavior. Its ObjectId query caster converts the primitive string to an ObjectId or throws a CastError; it does not JSON-parse string contents into selector operators (lib/schema/objectid.js, cast and castForQuery). The accompanying selector_path_string evidence identifies a direct, unmodified Express named URL parameter. Express's route matcher supplies that parameter as a decoded primitive string, not a parsed body/query object. JSON-looking text or $ne in that string cannot introduce query operators. For this exact input and operation, syntax/operator protection can be established without an application validator; externally controlled source coverage remains yes even though the value cannot control operators. Invalid IDs/error handling, business validation, authorization and stored-content rendering are separate claims. These facts must not be applied to body/query objects, modified parameters, custom _id schemas, unknown hooks or other operations."}
	case MongoDBDocumentContract:
		return &analysis.APIModel{ID: id, Library: "mongodb", Reference: "https://www.mongodb.com/docs/manual/reference/operator/query/",
			Semantics: "MongoDB document query language, reached through the native Node.js driver (npm package mongodb). The driver has no schema and casts nothing. " +
				"Where a field value is expected, an object is read as operators ($ne, $gt, $in, $regex, $exists, ...); a primitive string, number or boolean is data, even when a string begins with $. " +
				"The operand of $eq and each element of $in or $nin is a compared value, never operators; a regular expression object inside $in still matches as a pattern. " +
				"A request-chosen top-level key or whole filter chooses the selector, including $where, $expr, $or and $nor. " +
				"$where, $function, $accumulator and the map, reduce and finalize functions of mapReduce run JavaScript text on the server. " +
				"Inside $expr and aggregation expressions a string that begins with $ is a field path or variable; $literal makes it data; inside $match outside $expr a string is data. " +
				"A request-chosen pipeline or stage can read other collections ($lookup, $unionWith) and write ($out, $merge). " +
				"In an update, operators such as $set name fields by key: a request object as the update, or as the operand of an operator, chooses which fields change; an array update is a pipeline. " +
				"$regex and a RegExp built from text take a pattern: request text in it is matched as a pattern unless its metacharacters are escaped. " +
				"A sort key, projection, field name, or collection or database name from the request chooses which field or data is read, unless the code limits it to fixed alternatives. " +
				"In a stored or replacement document, values are data, not operators. Options such as limit and skip are not selectors."}
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

// DocumentOperationProtocol is the question protocol of a database package
// operation judged by its query language (contract MongoDBDocumentContract). It
// is selected by the record's contract, never for the NoSQL family as a whole.
const DocumentOperationProtocol = "document-operation-v2"

// DocumentOperationQuestions asks what the call is, and whether an input exists
// that changes the operation beyond what the code lists. The request is small
// and names no driver method. v1 asked what the request "controls": a request
// that picks one of two listed names does control the name, and safe lookups
// were reported. The wording below cleared them on the same evidence.
func DocumentOperationQuestions() []Question {
	return []Question{
		{"operation", "What is the call? Decide from receiver_path and the call itself."},
		{"request_control", "Is there an input an attacker can send that changes this operation beyond the choices the code itself lists? Work it out concretely: take each request value from where it is read, apply every conversion, check and helper in source in order, and see what arrives at the call. Selecting one of several alternatives that the code lists (a key of a constant map, a member of a constant list, a field of a schema that drops unknown keys) is not such an input; neither is a value that arrives as a number, as one complete quoted literal, or with every special character removed or escaped. A check counts only when it runs before the call and stops the request, by returning or throwing, for every value it does not allow; a check on another value, or a fallback that keeps the original value, protects nothing. One such input on one path is enough."},
	}
}

// DocumentOperationChoices returns the closed answers of a document operation question.
func DocumentOperationChoices(name string) []map[string]string {
	switch name {
	case "operation":
		return []map[string]string{
			{"value": "database_query", "description": "A MongoDB operation on a collection, cursor, database or client that selects, reads, counts, updates, deletes, aggregates or runs a command, and takes a filter, an update, a pipeline, a command document, or a field, collection or database name."},
			{"value": "stores_document", "description": "A MongoDB operation whose request-derived argument is only a document to store: an insert, or the replacement document of a replace."},
			{"value": "not_database_operation", "description": "Not a MongoDB server operation: receiver_path does not lead to a collection, cursor, database or client, or the call is a method of a result value or a constructor of a value."},
			{"value": "cannot_tell", "description": "The supplied source does not show what the call is."},
		}
	case "request_control":
		return []map[string]string{
			{"value": "operator", "description": "Yes: a JSON object or array such as {\"$ne\": \"\"} arrives where a compared value is expected, or the request supplies a top-level key or a whole filter, stage, pipeline or command."},
			{"value": "expression_text", "description": "Yes: text the attacker writes arrives inside JavaScript that the server runs, or as a string beginning with $ inside an aggregation or update-pipeline expression."},
			{"value": "pattern", "description": "Yes: regular-expression metacharacters arrive inside a pattern."},
			{"value": "name", "description": "Yes: a field, sort, projection, collection or database name that the code does not list arrives as a name."},
			{"value": "written_fields", "description": "Yes: a field name that the code does not list arrives as a key of an update operator's operand or of a stored or replacement document."},
			{"value": "data_only", "description": "No: on every path each request value arrives only as a compared primitive value, an operand of $eq, $in or $literal, a number, one complete literal, escaped or filtered text, or one of the alternatives the code lists."},
			{"value": "cannot_tell", "description": "The supplied source does not show what a check, conversion or helper on the way does."},
		}
	}
	return nil
}

// DocumentOperationControls are the request_control answers that are a finding.
var DocumentOperationControls = map[string]bool{"operator": true, "expression_text": true, "pattern": true, "name": true, "written_fields": true}

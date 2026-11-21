package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// DeserializationProtocol is the question-set version of the family.
const DeserializationProtocol = "deserialization-components-v1"

// Contract identifiers of the verified deserializer operations.
const (
	PythonPickle     = "python-pickle-v1"
	PythonYAML       = "python-yaml-v1"
	PythonJSONPickle = "python-jsonpickle-v1"
	NodeSerialize    = "node-serialize-v1"
	JSYAML           = "js-yaml-v1"
	PHPUnserialize   = "php-unserialize-v1"
	PHPSymfonyYAML   = "php-symfony-yaml-v1"
)

var deserializationContracts = []string{PythonPickle, PythonYAML, PythonJSONPickle, NodeSerialize, JSYAML, PHPUnserialize, PHPSymfonyYAML}

// DeserializationContract returns the semantics of a verified deserializer
// operation, or nil for an unknown identifier.
func DeserializationContract(id string) *analysis.APIModel {
	semantics := map[string]string{
		PythonPickle:     "pickle, _pickle, cPickle, dill and cloudpickle load, loads and Unpickler(...).load deserialize data with code execution by format design.",
		PythonYAML:       "PyYAML load and load_all use their verified loader or exact-version default; unsafe_load and unsafe_load_all allow code execution by format design, full_load and full_load_all have restricted types, and safe and base loaders produce plain data.",
		PythonJSONPickle: "jsonpickle.decode allows code execution by format design even with safe=True.",
		NodeSerialize:    "node-serialize unserialize and funcster deepDeserialize deserialize data with code execution by format design.",
		JSYAML:           "js-yaml load and loadAll use their verified schema or exact-version default; versions below 4.0.0 default to a full schema that allows code execution by format design, and 4.0.0 and later default to plain data. Below 4.0.0 an explicit full schema can override safeLoad or safeLoadAll.",
		PHPUnserialize:   "PHP unserialize can instantiate data-selected classes unless allowed_classes is false. A literal list restricts the classes. Object injection impact depends on which classes are available.",
		PHPSymfonyYAML:   "Symfony Yaml::parse with PARSE_OBJECT supports object injection. The effect depends on which classes are available.",
	}
	s, ok := semantics[id]
	if !ok {
		return nil
	}
	return &analysis.APIModel{ID: id, Library: id, Reference: "https://cwe.mitre.org/data/definitions/502.html", Semantics: s + " Decoding preserves the origin of the bytes and provides no protection; unkeyed hashes provide no integrity protection."}
}

func deserializationQuestionNames() []string {
	return []string{"deserialization_exposure", "integrity_control", "class_restriction", "protection_coverage"}
}

// DeserializationQuestions returns the family's questions in protocol order.
func DeserializationQuestions() []Question {
	return []Question{
		{"deserialization_exposure", "Do request-controlled bytes reach the verified deserializer's data operand (vulnerable, protected, not_applicable, unknown)? Treat use.deserialization.capability as a fixed contract fact."},
		{"integrity_control", "Does a keyed check enforce verification of the same bytes before the call (none, verified_before_decode, present_inadequate, unknown), using use.deserialization.controls for recorded control kinds and treating unkeyed hashes, encodings and format checks as providing no integrity?"},
		{"class_restriction", "Does an allow-list limit classes named by the data to classes with no dangerous behavior (adequate, inadequate, unknown), or is the list missing (none)?"},
		{"protection_coverage", "Is the protection enforced on every path (complete, incomplete, unknown), with missing flow classified as unknown?"},
	}
}

func deserializationChoices(question string) []string {
	switch question {
	case "deserialization_exposure":
		return []string{"vulnerable", "protected", "not_applicable", "unknown"}
	case "integrity_control":
		return []string{"none", "verified_before_decode", "present_inadequate", "unknown"}
	default:
		return []string{"none", "adequate", "inadequate", "unknown"}
	}
}

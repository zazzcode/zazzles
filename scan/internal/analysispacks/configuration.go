package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// ConfigurationProtocol versions the configuration claim questions (D-3).
const ConfigurationProtocol = "configuration-components-v4"

// ConfigurationRoles are the evidence obligations of a configuration claim.
func ConfigurationRoles() []string { return []string{"setting", "scope"} }

func configurationQuestionNames() []string {
	return []string{"setting_effect", "weakness", "mitigation"}
}

// ConfigurationQuestions returns the questions in protocol order.
func ConfigurationQuestions() []Question {
	return []Question{
		{"setting_effect", "Is the recorded setting applied to the deployed application, given configuration.scope and the deployment-mapping evidence (in_effect, not_in_effect, unknown)?"},
		{"weakness", "Given configuration.joined, does the setting weaken this application (weakens, benign, unknown)?"},
		{"mitigation", "Do the recorded configuration.mitigations remove the weakness (none, adequate, inadequate, unknown)?"},
	}
}

// ConfigurationChoices lists the accepted answers for a configuration question.
func ConfigurationChoices(question string) []map[string]string {
	switch question {
	case "setting_effect":
		return choicePairs(
			[2]string{"in_effect", "The recorded setting is applied to the deployed application."},
			[2]string{"not_in_effect", "The recorded setting is not applied to the deployed application."},
			[2]string{"unknown", "The supplied evidence does not establish whether the setting is applied."},
		)
	case "weakness":
		return choicePairs(
			[2]string{"weakens", "The joined application facts make the setting a weakness."},
			[2]string{"benign", "The joined application facts do not make the setting a weakness."},
			[2]string{"unknown", "The supplied evidence does not establish whether the setting weakens the application."},
		)
	case "mitigation":
		return choicePairs(
			[2]string{"none", "No mitigation is recorded."},
			[2]string{"adequate", "A recorded mitigation removes the weakness."},
			[2]string{"inadequate", "A recorded mitigation does not remove the weakness."},
			[2]string{"unknown", "The supplied evidence does not establish whether a mitigation removes the weakness."},
		)
	}
	return nil
}

// ConfigurationCheckCWE is the CWE of one configuration check.
func ConfigurationCheckCWE(check string) string {
	switch check {
	case analysis.CheckDirectoryListing:
		return "CWE-548"
	case analysis.CheckCSRFDisabled:
		return "CWE-352"
	case analysis.CheckSessionCookieScript:
		return "CWE-1004"
	case analysis.CheckSessionCookieTransport:
		return "CWE-614"
	case analysis.CheckDebugEnabled:
		return "CWE-489"
	case analysis.CheckScheduledPrivileged:
		return "CWE-732"
	}
	return ""
}

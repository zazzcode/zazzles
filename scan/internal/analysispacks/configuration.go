package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// ConfigurationProtocol versions the configuration claim: its questions,
// the meaning of its evidence roles and the instruction sent with them.
const ConfigurationProtocol = "configuration-components-v5"

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
			[2]string{"in_effect", "A recorded fact puts the file in the deployed application (config_installed, deployed_file or schedule), and the setting's scope applies there."},
			[2]string{"not_in_effect", "A recorded fact shows the setting is overridden, or its scope is not part of the deployed application."},
			[2]string{"unknown", "No recorded fact puts the file in the deployed application, or its scope is not mapped."},
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

// ConfigurationCheckEffect states what a check's directive does, as its
// documentation describes it. It says nothing about a particular
// application: whether the effect is a weakness there is the claim.
func ConfigurationCheckEffect(check string) string {
	switch check {
	case analysis.CheckDirectoryListing:
		return "Apache Options Indexes and nginx autoindex on make the server answer a request for a directory that has no index file with a list of the files in it."
	case analysis.CheckCSRFDisabled:
		return "framework.csrf_protection false turns off Symfony's CSRF token support, so a state-changing request is accepted without a token unless the code validates one itself."
	case analysis.CheckSessionCookieScript:
		return "A session cookie without HttpOnly can be read by scripts running in the page."
	case analysis.CheckSessionCookieTransport:
		return "A session cookie without Secure is also sent over plain HTTP."
	case analysis.CheckDebugEnabled:
		return "APP_ENV=dev, APP_DEBUG, display_errors and the web profiler show internal state, such as stack traces and configuration, in responses."
	case analysis.CheckRemoteInclude:
		return "allow_url_include on lets include and require load and run PHP code from a URL, such as http:// or data://, so an include whose operand a request controls can run code the requester supplies. PHP reads php.ini from its configuration path; whether it reads one in another directory depends on the server interface."
	case analysis.CheckScheduledPrivileged:
		return "cron runs the scheduled command as the named user, and each file that command executes runs with that user's privileges, so a user who can rewrite one of those files chooses what runs with them."
	}
	return ""
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
	case analysis.CheckRemoteInclude:
		return "CWE-98"
	case analysis.CheckScheduledPrivileged:
		return "CWE-732"
	}
	return ""
}

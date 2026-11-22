package report

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

var configurationFindingTypes = []analysis.FindingType{
	{ID: "insecure-configuration", Label: "Insecure Configuration", Coverage: "bounded framework and deployment configuration analysis",
		Description:    "A framework or deployment setting weakens the application in a way the joined facts make concrete (CWE-548, CWE-352, CWE-1004, CWE-614, CWE-489, CWE-732, CWE-269).",
		Interpretation: "The record holds one setting, its scope and the application facts it joins. The scanner does not decide that the setting is a defect. A hardened value is not recorded.",
		Remediation:    "Change the setting, or keep the joined condition from applying: disable directory listing where uploads are stored, keep CSRF protection on for state-changing entries, mark the session cookie HttpOnly and Secure, and do not run a writable project file from a privileged schedule."},
}

func configurationRule(u analysis.CandidateUse) (string, string) {
	check := ""
	if u.Configuration != nil {
		check = u.Configuration.Check
	}
	return "scan/insecure-configuration", analysispacks.ConfigurationCheckCWE(check)
}

func configurationGuidance(u analysis.CandidateUse) Guidance {
	check := ""
	if u.Configuration != nil {
		check = u.Configuration.Check
	}
	switch check {
	case analysis.CheckDirectoryListing:
		return Guidance{Title: "Turn directory listing off where files are served", Actions: []string{"Remove Indexes from the directory that is served.", "Store uploads outside any listed directory."}}
	case analysis.CheckCSRFDisabled:
		return Guidance{Title: "Require a CSRF token on state-changing entries", Actions: []string{"Leave framework.csrf_protection enabled.", "Validate a token on every entry that changes state."}}
	case analysis.CheckSessionCookieScript:
		return Guidance{Title: "Keep the session cookie out of scripts", Actions: []string{"Set cookie_httponly to true."}}
	case analysis.CheckSessionCookieTransport:
		return Guidance{Title: "Send the session cookie only over HTTPS", Actions: []string{"Set cookie_secure to true or auto."}}
	case analysis.CheckDebugEnabled:
		return Guidance{Title: "Keep debug output out of the deployed application", Actions: []string{"Deploy with APP_ENV=prod and APP_DEBUG=0.", "Leave display_errors off and the web profiler in the dev and test environments."}}
	case analysis.CheckScheduledPrivileged:
		return Guidance{Title: "Do not schedule a file a less privileged user can rewrite", Actions: []string{"Run the scheduled command as the user that owns the file, or make that file writable only by the schedule user."}}
	}
	return Guidance{Title: "Review the recorded configuration setting", Actions: []string{"Compare the setting with the joined application facts."}}
}

func describeConfiguration(u analysis.CandidateUse, f *analysis.Finding) {
	x := u.Configuration
	if x == nil {
		return
	}
	a := u.Assessment
	confirmed := a.Status == "completed" && a.QuestionVersion == analysispacks.ConfigurationProtocol && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability"
	f.Title = "Configuration setting needs review"
	f.Summary = "Setting " + x.Check + " is recorded with the application facts it joins (" + analysispacks.ConfigurationCheckCWE(x.Check) + ")."
	if f.Status != "protected_for_claim" {
		f.Title = "Configuration setting needs review"
	}
	if confirmed {
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title = "Insecure configuration supported by source analysis"
	}
	f.Protection = "Configuration assessment: effect " + displayLabel(a.Answers["setting_effect"]) + ", weakness " + displayLabel(a.Answers["weakness"]) + ", mitigation " + displayLabel(a.Answers["mitigation"])
}

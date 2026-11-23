package langphp

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// configurationCase is one row of a configuration case table. checks
// selects the checks the row is about. want is every candidate of those
// checks, as "check file:line". joined, lacks, scope and gaps are keyed by
// the same string.
type configurationCase struct {
	name    string
	fixture string
	overlay map[string]string
	checks  []string
	want    []string
	// joined facts each candidate must carry, as "kind file:line text".
	joined map[string][]string
	// lacks are joined fact kinds a candidate must not carry.
	lacks map[string][]string
	// scope is the candidate's scope evidence, as "file:line text".
	scope       map[string]string
	mitigations map[string][]string
	gaps        map[string][]string
	reportGaps  []string
}

func runConfigurationCases(t *testing.T, cases []configurationCase) {
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := phpAnalyze(t, overlayFixture(t, tt.fixture, tt.overlay), "")
			records := configurationRecords(r)
			got := sortedKeys(records, func(k string) bool { return hasPrefixAny(k, tt.checks) })
			if !slices.Equal(got, tt.want) {
				t.Fatalf("candidates %q, want %q", got, tt.want)
			}
			for key, facts := range tt.joined {
				have := joinedFacts(records[key])
				for _, fact := range facts {
					if !slices.Contains(have, fact) {
						t.Errorf("%s lacks joined fact %q; has %q", key, fact, have)
					}
				}
			}
			for key, kinds := range tt.lacks {
				for _, e := range records[key].Configuration.Joined {
					if slices.Contains(kinds, e.Kind) {
						t.Errorf("%s must not join %s %q", key, e.Kind, e.Text)
					}
				}
			}
			for key, want := range tt.scope {
				scope := records[key].Completeness.Evidence["scope"]
				if len(scope) != 1 || at(scope[0].Span)+" "+scope[0].Text != want {
					t.Errorf("%s scope evidence %+v, want %q", key, scope, want)
				}
			}
			for key, want := range tt.mitigations {
				var have []string
				for _, e := range records[key].Configuration.Mitigations {
					have = append(have, at(e.Span))
				}
				if !slices.Equal(have, want) {
					t.Errorf("%s mitigations %q, want %q", key, have, want)
				}
			}
			for key, want := range tt.gaps {
				if have := gapKinds(records[key].Gaps); !slices.Equal(have, want) {
					t.Errorf("%s gaps %q, want %q", key, have, want)
				}
				if have := gapKinds(records[key].Completeness.Blockers); !slices.Equal(have, want) {
					t.Errorf("%s blockers %q, want %q", key, have, want)
				}
			}
			if tt.reportGaps != nil {
				var have []string
				for _, g := range r.Gaps {
					if strings.HasPrefix(g.Kind, "config") {
						have = append(have, g.Kind+" "+g.At.File)
					}
				}
				if !slices.Equal(have, tt.reportGaps) {
					t.Errorf("report gaps %q, want %q", have, tt.reportGaps)
				}
			}
		})
	}
}

const (
	symfonyConfiguration  = "testdata/symfony/configuration"
	transferConfiguration = "testdata/symfony/configuration-transfer"
	plainConfiguration    = "testdata/configuration"
	frameworkYAML         = "config/packages/framework.yaml"
	profilerYAML          = "config/packages/web_profiler.yaml"
)

func TestSymfonyConfiguration(t *testing.T) {
	csrf, script, transport, debug := []string{analysis.CheckCSRFDisabled}, []string{analysis.CheckSessionCookieScript}, []string{analysis.CheckSessionCookieTransport}, []string{analysis.CheckDebugEnabled}
	yaml := func(text string) map[string]string { return map[string]string{frameworkYAML: text} }
	guarded := strings.Replace(mustRead(t, symfonyConfiguration+"/src/Controller/NoteController.php"),
		"        $note->setBody($request->request->get('title'));",
		"        if (!$this->isCsrfTokenValid('note', $request->request->get('token'))) {\n            return new Response('', 403);\n        }\n        $note->setBody($request->request->get('title'));", 1)
	manyEntries := "<?php\nnamespace App\\Controller;\nuse App\\Entity\\Note;\nuse Symfony\\Component\\HttpFoundation\\Request;\nuse Symfony\\Component\\HttpFoundation\\Response;\nuse Symfony\\Component\\Routing\\Attribute\\Route;\nclass ManyController {\n"
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		manyEntries += "  #[Route('/locked/many/" + name + "/{note}', methods: ['POST'])]\n  public function " + name + "(Note $note, Request $request): Response { $note->setBody($request->request->get('body')); return new Response(''); }\n"
	}
	manyEntries += "}\n"
	runConfigurationCases(t, []configurationCase{
		{name: "CF-01 csrf_protection false joins the login-required entries that write", fixture: symfonyConfiguration, checks: csrf,
			want: []string{"csrf_disabled " + frameworkYAML + ":2"},
			joined: map[string][]string{"csrf_disabled " + frameworkYAML + ":2": {
				"config_installed Dockerfile:3 copied . to /srv/site including " + frameworkYAML,
				"state_changing_entry src/Controller/NoteController.php:13 POST /locked/{note}/write authentication required",
				"state_changing_entry src/Controller/NoteController.php:20 POST /locked/{note}/rename authentication required",
			}},
			scope:       map[string]string{"csrf_disabled " + frameworkYAML + ":2": "composer.json:1 project ."},
			mitigations: map[string][]string{"csrf_disabled " + frameworkYAML + ":2": nil}},
		{name: "CF-01 the public entry that writes is not joined", fixture: symfonyConfiguration, checks: csrf,
			want: []string{"csrf_disabled " + frameworkYAML + ":2"}},
		{name: "CF-01 at most eight entries, sorted by name", fixture: symfonyConfiguration, checks: csrf,
			overlay: map[string]string{"src/Controller/ManyController.php": manyEntries},
			want:    []string{"csrf_disabled " + frameworkYAML + ":2"}},
		{name: "CF-02 csrf_protection enabled false", fixture: symfonyConfiguration, checks: csrf,
			overlay: yaml("framework:\n  csrf_protection:\n    enabled: false\n"),
			want:    []string{"csrf_disabled " + frameworkYAML + ":3"}},
		{name: "CF-03 csrf_protection true", fixture: symfonyConfiguration, checks: csrf, overlay: yaml("framework:\n  csrf_protection: true\n")},
		{name: "CF-03 csrf_protection null", fixture: symfonyConfiguration, checks: csrf, overlay: yaml("framework:\n  csrf_protection: ~\n")},
		{name: "CF-03 csrf_protection absent", fixture: symfonyConfiguration, checks: csrf, overlay: yaml("framework:\n  secret: x\n")},
		{name: "CF-04 csrf_protection false only under when@test", fixture: symfonyConfiguration, checks: csrf,
			overlay: yaml("framework:\n  secret: x\nwhen@test:\n  framework:\n    csrf_protection: false\nwhen@dev:\n  framework:\n    csrf_protection: false\n")},
		{name: "CF-04 when@prod is the deployed environment", fixture: symfonyConfiguration, checks: csrf,
			overlay: yaml("framework:\n  secret: x\nwhen@prod:\n  framework:\n    csrf_protection: false\n"),
			want:    []string{"csrf_disabled " + frameworkYAML + ":5"},
			scope:   map[string]string{"csrf_disabled " + frameworkYAML + ":5": frameworkYAML + ":3 when@prod"}},
		{name: "CF-04 when@prod true overrides a top-level false", fixture: symfonyConfiguration, checks: csrf,
			overlay: yaml("framework:\n  csrf_protection: false\nwhen@prod:\n  framework:\n    csrf_protection: true\n")},
		{name: "CF-05 isCsrfTokenValid is recorded as mitigation", fixture: symfonyConfiguration, checks: csrf,
			overlay:     map[string]string{"src/Controller/NoteController.php": guarded},
			want:        []string{"csrf_disabled " + frameworkYAML + ":2"},
			mitigations: map[string][]string{"csrf_disabled " + frameworkYAML + ":2": {"src/Controller/NoteController.php:23"}}},
		{name: "CF-06 cookie_httponly false", fixture: symfonyConfiguration, checks: script,
			want: []string{"session_cookie_script_readable " + frameworkYAML + ":4"},
			joined: map[string][]string{"session_cookie_script_readable " + frameworkYAML + ":4": {
				"session_authenticated " + frameworkYAML + ":4 session_authenticated: yes"}}},
		{name: "CF-06 ini_set with a literal false value", fixture: symfonyConfiguration, checks: script,
			overlay: map[string]string{frameworkYAML: "framework:\n  secret: x\n", "src/Boot.php": "<?php\nini_set('session.cookie_httponly', '0');\nini_set('session.cookie_httponly', false);\nini_set('session.cookie_httponly', '1');\n"},
			want:    []string{"session_cookie_script_readable src/Boot.php:2", "session_cookie_script_readable src/Boot.php:3"}},
		{name: "CF-07 cookie_httponly true", fixture: symfonyConfiguration, checks: script, overlay: yaml("framework:\n  session:\n    cookie_httponly: true\n")},
		{name: "CF-07 cookie_httponly absent", fixture: symfonyConfiguration, checks: script, overlay: yaml("framework:\n  session:\n    handler_id: null\n")},
		{name: "CF-08 cookie_secure false", fixture: symfonyConfiguration, checks: transport,
			want: []string{"session_cookie_insecure_transport " + frameworkYAML + ":5"}},
		{name: "CF-09 cookie_secure auto", fixture: symfonyConfiguration, checks: transport, overlay: yaml("framework:\n  session:\n    cookie_secure: auto\n")},
		{name: "CF-10 web_profiler toolbar at the top level", fixture: symfonyConfiguration, checks: debug,
			overlay: map[string]string{"deploy/env.stage": "APP_ENV=prod\n", "deploy/php.ini": "display_errors = Off\n"},
			want:    []string{"debug_enabled " + profilerYAML + ":2"}},
		{name: "CF-11 web_profiler toolbar under when@dev", fixture: symfonyConfiguration, checks: debug,
			overlay: map[string]string{"deploy/env.stage": "APP_ENV=prod\n", "deploy/php.ini": "display_errors = Off\n", profilerYAML: "when@dev:\n  web_profiler:\n    toolbar: true\n"}},
		{name: "CF-12 unparseable framework.yaml", fixture: symfonyConfiguration, checks: append(append(csrf, script...), transport...),
			overlay:    yaml("framework:\n  csrf_protection: [false\n"),
			reportGaps: []string{"config_file_unread " + frameworkYAML}},
	})
	t.Run("two settings of one file are two places", func(t *testing.T) {
		records := configurationRecords(phpAnalyze(t, symfonyConfiguration, ""))
		a, b := records["csrf_disabled "+frameworkYAML+":2"].Sink.Span, records["session_cookie_script_readable "+frameworkYAML+":4"].Sink.Span
		text := mustRead(t, symfonyConfiguration+"/"+frameworkYAML)
		if text[a.StartByte:a.EndByte] != "  csrf_protection: false" || text[b.StartByte:b.EndByte] != "    cookie_httponly: false" {
			t.Fatalf("spans %+v %+v", a, b)
		}
	})
	t.Run("CF-01 the entry list is capped and ordered", func(t *testing.T) {
		r := phpAnalyze(t, overlayFixture(t, symfonyConfiguration, map[string]string{"src/Controller/ManyController.php": manyEntries}), "")
		var entries []string
		for _, e := range configurationRecords(r)["csrf_disabled "+frameworkYAML+":2"].Configuration.Joined {
			if e.Kind == "state_changing_entry" {
				entries = append(entries, e.Text)
			}
		}
		if len(entries) != 8 || !slices.IsSorted(entries) || strings.Contains(strings.Join(entries, "\n"), "/open/") {
			t.Fatalf("entries %q", entries)
		}
	})
}

func TestDeployConfiguration(t *testing.T) {
	listing, debug, schedule := []string{analysis.CheckDirectoryListing}, []string{analysis.CheckDebugEnabled}, []string{analysis.CheckScheduledPrivileged}
	cookies := []string{analysis.CheckSessionCookieScript, analysis.CheckSessionCookieTransport}
	base := mustRead(t, symfonyConfiguration+"/Dockerfile")
	quiet := map[string]string{profilerYAML: removed, "deploy/php.ini": "display_errors = Off\n"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range quiet {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	runConfigurationCases(t, []configurationCase{
		{name: "DP-01 Apache listing on the mapped document root joins the upload destination", fixture: symfonyConfiguration, checks: listing,
			want: []string{"directory_listing deploy/site.conf:2", "directory_listing deploy/site.conf:5"},
			joined: map[string][]string{"directory_listing deploy/site.conf:2": {
				"scope_mapping deploy/site.conf:2 public",
				"scope_served deploy/site.conf:2 served yes directory public",
				"config_installed Dockerfile:4 deploy/site.conf is copied into the web server configuration",
				"upload_destination src/Controller/NoteController.php:38 upload destination /public/media is inside public",
			}},
			scope: map[string]string{"directory_listing deploy/site.conf:2": "deploy/site.conf:1 /srv/site/public"},
			gaps:  map[string][]string{"directory_listing deploy/site.conf:2": nil}},
		{name: "DP-02 the same listing with no upload action", fixture: symfonyConfiguration, checks: listing,
			overlay: map[string]string{"config/services.yaml": removed, "src/Controller/NoteController.php": "<?php\nnamespace App\\Controller;\nuse Symfony\\Component\\HttpFoundation\\Response;\nuse Symfony\\Component\\Routing\\Attribute\\Route;\nclass NoteController {\n  #[Route('/')]\n  public function home(): Response { return new Response(''); }\n}\n"},
			want:    []string{"directory_listing deploy/site.conf:2", "directory_listing deploy/site.conf:5"},
			lacks:   map[string][]string{"directory_listing deploy/site.conf:2": {"upload_destination"}}},
		{name: "DP-03 listing on a directory outside the document root", fixture: symfonyConfiguration, checks: listing,
			want: []string{"directory_listing deploy/site.conf:2", "directory_listing deploy/site.conf:5"},
			joined: map[string][]string{"directory_listing deploy/site.conf:5": {
				"scope_mapping deploy/site.conf:5 docs", "scope_served deploy/site.conf:5 served no directory docs"}},
			lacks: map[string][]string{"directory_listing deploy/site.conf:5": {"upload_destination"}}},
		{name: "DP-04 Options -Indexes and None", fixture: symfonyConfiguration, checks: listing,
			overlay: map[string]string{"deploy/site.conf": "<Directory /srv/site/public>\n    Options -Indexes +FollowSymLinks\n</Directory>\n<Directory /srv/site/docs>\n    Options None\n</Directory>\n"}},
		{name: "DP-04 the common Options forms that include Indexes", fixture: symfonyConfiguration, checks: listing,
			overlay: map[string]string{"deploy/site.conf": "<Directory /srv/site/public>\n    Options FollowSymLinks\n    Options +indexes\n</Directory>\n<Directory /srv/site/docs>\n    Options All\n</Directory>\n"},
			want:    []string{"directory_listing deploy/site.conf:3", "directory_listing deploy/site.conf:6"}},
		{name: "DP-05 deployed environment file with APP_ENV=dev", fixture: symfonyConfiguration, checks: debug, overlay: quiet,
			want:   []string{"debug_enabled deploy/env.stage:2"},
			joined: map[string][]string{"debug_enabled deploy/env.stage:2": {"deployed_file Dockerfile:5 deploy/env.stage -> /srv/site/.env.local"}},
			scope:  map[string]string{"debug_enabled deploy/env.stage:2": "Dockerfile:5 deploy/env.stage -> /srv/site/.env.local"}},
		{name: "DP-05 APP_DEBUG=1 is its own setting at its own line", fixture: symfonyConfiguration, checks: debug,
			overlay: with(map[string]string{"deploy/env.stage": "APP_ENV=prod\n\nAPP_DEBUG=1\n"}),
			want:    []string{"debug_enabled deploy/env.stage:3"}},
		{name: "DP-06 a prod file copied over a dev project .env", fixture: symfonyConfiguration, checks: debug,
			overlay: with(map[string]string{".env": "APP_ENV=dev\n", "deploy/env.stage": "APP_ENV=prod\n"})},
		{name: "DP-06 the project .env when nothing overrides it", fixture: symfonyConfiguration, checks: debug,
			overlay: with(map[string]string{".env": "APP_ENV=dev\n", "Dockerfile": strings.Replace(base, "COPY deploy/env.stage /srv/site/.env.local\n", "", 1)}),
			want:    []string{"debug_enabled .env:1"}},
		{name: "DP-07 php.ini display_errors On", fixture: symfonyConfiguration, checks: debug,
			overlay: map[string]string{profilerYAML: removed, "deploy/env.stage": "APP_ENV=prod\n"},
			want:    []string{"debug_enabled deploy/php.ini:2"}},
		{name: "DP-07 php.ini hardened cookie values record nothing", fixture: symfonyConfiguration, checks: cookies,
			overlay: map[string]string{frameworkYAML: "framework:\n  secret: x\n"}},
		{name: "DP-07 php.ini cookie directives", fixture: symfonyConfiguration, checks: cookies,
			overlay: map[string]string{frameworkYAML: "framework:\n  secret: x\n", "deploy/php.ini": "session.cookie_httponly = 0 ; off\nsession.cookie_secure = Off\n"},
			want:    []string{"session_cookie_insecure_transport deploy/php.ini:2", "session_cookie_script_readable deploy/php.ini:1"}},
		{name: "DP-08 root cron line, script, and a chown of the file the script runs", fixture: symfonyConfiguration, checks: schedule,
			want: []string{"scheduled_privileged_writable Dockerfile:7"},
			joined: map[string][]string{"scheduled_privileged_writable Dockerfile:7": {
				"schedule Dockerfile:7 root runs cd /srv/site && sh tools/tick.sh",
				"chain tools/tick.sh:2 the scheduled script runs tools/job.php",
				"ownership Dockerfile:6 web owns /srv/site/tools/job.php, not the schedule user root",
			}}},
		{name: "DP-09 without the chown", fixture: symfonyConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": strings.Replace(base, "RUN chown web:web /srv/site/tools/job.php\n", "", 1)}},
		{name: "DP-10 the cron line's user is the owner", fixture: symfonyConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": strings.Replace(base, "* root cd", "* web cd", 1)}},
		{name: "DP-10 a later chown back to the schedule user", fixture: symfonyConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": strings.Replace(base, "RUN echo", "RUN chown root /srv/site/tools/job.php\nRUN echo", 1)}},
		{name: "DP-08 a relative path with no cd is not resolved", fixture: symfonyConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": strings.Replace(base, "cd /srv/site && sh", "sh", 1)}},
		{name: "DP-08 the official-image RUN idiom with semicolons", fixture: symfonyConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": strings.Replace(base, "RUN chown web:web /srv/site/tools/job.php\n", "RUN set -eux; \\\n    chown -R web:web /srv/site/tools; \\\n    true\n", 1)},
			want:    []string{"scheduled_privileged_writable Dockerfile:9"},
			joined: map[string][]string{"scheduled_privileged_writable Dockerfile:9": {
				"chain tools/tick.sh:1 the scheduled script runs tools/tick.sh",
				"ownership Dockerfile:7 web owns /srv/site/tools, not the schedule user root"}}},
		{name: "DP-11 transfer: nginx autoindex on the web root", fixture: transferConfiguration, checks: listing,
			want: []string{"directory_listing nginx/site.conf:3", "directory_listing public/files/.htaccess:1"},
			joined: map[string][]string{"directory_listing nginx/site.conf:3": {
				"scope_served nginx/site.conf:3 served yes directory public",
				"config_installed Dockerfile:4 nginx/site.conf is copied into the web server configuration"}}},
		{name: "DP-12 transfer: crontab file installed for the default user, script made chmod 777", fixture: transferConfiguration, checks: schedule,
			want: []string{"scheduled_privileged_writable schedule/crontab:2", "scheduled_privileged_writable schedule/crontab:3"},
			joined: map[string][]string{"scheduled_privileged_writable schedule/crontab:2": {
				"schedule schedule/crontab:2 root runs /srv/app/jobs/report.sh",
				"chain jobs/report.sh:1 the scheduled script runs /srv/app/jobs/report.sh",
				"ownership Dockerfile:5 mode 777 lets users other than root write /srv/app/jobs/report.sh"}},
			scope: map[string]string{"scheduled_privileged_writable schedule/crontab:2": "Dockerfile:6 crontab /srv/app/schedule/crontab installed for root"}},
		{name: "DP-13 transfer: chown -R on the directory holding the script", fixture: transferConfiguration, checks: schedule,
			want: []string{"scheduled_privileged_writable schedule/crontab:2", "scheduled_privileged_writable schedule/crontab:3"},
			joined: map[string][]string{"scheduled_privileged_writable schedule/crontab:3": {
				"ownership Dockerfile:5 web owns /srv/app/tasks, not the schedule user root"}}},
		{name: "DP-12 transfer: the crontab installed after USER runs as that user", fixture: transferConfiguration, checks: schedule,
			overlay: map[string]string{"Dockerfile": "FROM scratch\nWORKDIR /srv/app\nCOPY . /srv/app\nRUN chown -R web /srv/app/tasks /srv/app/jobs\nUSER web\nRUN crontab /srv/app/schedule/crontab\n"}},
		{name: "DP-14 transfer: .htaccess listing in public/files", fixture: transferConfiguration, checks: listing,
			want: []string{"directory_listing nginx/site.conf:3", "directory_listing public/files/.htaccess:1"},
			joined: map[string][]string{"directory_listing public/files/.htaccess:1": {
				"scope_mapping public/files/.htaccess:1 public/files",
				"scope_served public/files/.htaccess:1 served yes directory public/files",
				"config_installed public/files/.htaccess:1 public/files/.htaccess is under the document root"}},
			gaps: map[string][]string{"directory_listing public/files/.htaccess:1": nil}},
		{name: "DP-14 transfer: .htaccess with no Dockerfile needs no mapping", fixture: transferConfiguration, checks: listing,
			overlay: map[string]string{"Dockerfile": removed, "nginx/site.conf": removed},
			want:    []string{"directory_listing public/files/.htaccess:1"},
			gaps:    map[string][]string{"directory_listing public/files/.htaccess:1": nil}},
		{name: "DP-14 transfer: .htaccess outside the document root is not served", fixture: transferConfiguration, checks: listing,
			overlay: map[string]string{"nginx/site.conf": removed, "public/files/.htaccess": removed, "jobs/.htaccess": "Options +Indexes\n"},
			want:    []string{"directory_listing jobs/.htaccess:1"},
			joined:  map[string][]string{"directory_listing jobs/.htaccess:1": {"scope_served jobs/.htaccess:1 served no directory jobs"}},
			lacks:   map[string][]string{"directory_listing jobs/.htaccess:1": {"config_installed"}}},
		{name: "DP-15 plain PHP: Apache listing with a move_uploaded_file destination in scope", fixture: plainConfiguration, checks: listing,
			want: []string{"directory_listing docker/site.conf:2"},
			joined: map[string][]string{"directory_listing docker/site.conf:2": {
				"scope_served docker/site.conf:2 served yes directory uploads",
				"upload_destination index.php:2 upload destination uploads is inside uploads"}}},
		{name: "DP-15 plain PHP: no Dockerfile, the scope matches by trailing segments", fixture: plainConfiguration, checks: listing,
			overlay: map[string]string{"Dockerfile": removed},
			want:    []string{"directory_listing docker/site.conf:2"},
			joined:  map[string][]string{"directory_listing docker/site.conf:2": {"scope_mapping docker/site.conf:2 uploads"}},
			gaps:    map[string][]string{"directory_listing docker/site.conf:2": nil}},
		{name: "DP-16 a COPY with a build argument leaves the mapping unresolved", fixture: plainConfiguration, checks: listing,
			overlay: map[string]string{"Dockerfile": "FROM scratch\nARG SRC\nCOPY ${SRC} /var/www/html\n"},
			want:    []string{"directory_listing docker/site.conf:2"},
			gaps:    map[string][]string{"directory_listing docker/site.conf:2": {"deploy_mapping_unresolved", "deploy_mapping_unresolved"}},
			lacks:   map[string][]string{"directory_listing docker/site.conf:2": {"upload_destination"}}},
		{name: "DP-16 no Dockerfile and a scope that matches no project directory", fixture: plainConfiguration, checks: listing,
			overlay: map[string]string{"Dockerfile": removed, "docker/site.conf": "<Directory /var/www/shared>\n    Options Indexes\n</Directory>\n"},
			want:    []string{"directory_listing docker/site.conf:2"},
			gaps:    map[string][]string{"directory_listing docker/site.conf:2": {"deploy_mapping_unresolved"}}},
	})
}

// TestDeployReadsStayInsideTheRoot covers paths a deployment file names.
// None of them may open a file outside the scan root.
func TestDeployReadsStayInsideTheRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "outside.env"), []byte("APP_ENV=dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "tick.sh"), []byte("#!/bin/sh\nphp /srv/site/tools/job.php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := mustRead(t, symfonyConfiguration+"/Dockerfile")
	rel, err := filepath.Rel(filepath.Join(os.TempDir(), "x"), outside)
	if err != nil {
		t.Fatal(err)
	}
	for name, overlay := range map[string]map[string]string{
		"COPY source with ..": {"Dockerfile": strings.Replace(base, "COPY deploy/env.stage", "COPY ../"+filepath.Base(outside)+"/outside.env", 1)},
		"cron script with ..": {"Dockerfile": strings.Replace(base, "sh tools/tick.sh", "sh ../../"+filepath.ToSlash(rel)+"/tick.sh", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			root := overlayFixture(t, symfonyConfiguration, overlay)
			r := phpAnalyze(t, root, "")
			for key, u := range configurationRecords(r) {
				if strings.Contains(key, "..") || strings.Contains(key, "outside") {
					t.Errorf("candidate from outside the root: %s", key)
				}
				for _, e := range u.Configuration.Joined {
					if strings.Contains(e.Span.File, "..") {
						t.Errorf("%s joins evidence outside the root: %s", key, e.Span.File)
					}
				}
			}
		})
	}
	t.Run("a symbolic link in the path is not followed", func(t *testing.T) {
		root := overlayFixture(t, symfonyConfiguration, map[string]string{"tools/tick.sh": removed})
		if err := os.Symlink(filepath.Join(outside, "tick.sh"), filepath.Join(root, "tools", "tick.sh")); err != nil {
			t.Skip("symbolic links are not available")
		}
		records := configurationRecords(phpAnalyze(t, root, ""))
		if got := sortedKeys(records, func(k string) bool { return strings.HasPrefix(k, analysis.CheckScheduledPrivileged) }); len(got) != 0 {
			t.Fatalf("the linked script was read: %q", got)
		}
	})
}

// TestConfigurationDeterminism scans a project whose Dockerfile gives two
// COPY destinations for one file twenty times. The records must not move.
func TestConfigurationDeterminism(t *testing.T) {
	dockerfile := "FROM scratch\nCOPY . /srv/site\nCOPY tools/tick.sh /usr/local/bin/tick.sh\nCOPY tools /opt/tools\nRUN chown -R web /srv/site\nRUN echo \"* * * * * root /usr/local/bin/tick.sh\" > /etc/cron.d/site\n"
	root := overlayFixture(t, symfonyConfiguration, map[string]string{"Dockerfile": dockerfile})
	var first []string
	for i := 0; i < 20; i++ {
		var got []string
		for key, u := range configurationRecords(phpAnalyze(t, root, "")) {
			got = append(got, key+" "+strings.Join(joinedFacts(u), "|"))
		}
		slices.Sort(got)
		if i == 0 {
			first = got
		} else if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs:\n%q\n%q", i, got, first)
		}
	}
	if len(first) == 0 {
		t.Fatal("no records")
	}
}

func TestAddressTrust(t *testing.T) {
	base := mustRead(t, symfonyConfiguration+"/Dockerfile")
	conf := mustRead(t, symfonyConfiguration+"/deploy/site.conf")
	for _, tt := range []struct {
		name, status, text string
		overlay            map[string]string
		gap                bool
	}{
		{"AT-01 no trusted_proxies and no proxy module", "not_configured", "", nil, false},
		{"AT-02 trusted_proxies with trusted_headers", "configured", "trusted_proxies=10.0.0.0/8; trusted_headers=x-forwarded-for,x-forwarded-proto",
			map[string]string{frameworkYAML: "framework:\n  trusted_proxies: '10.0.0.0/8'\n  trusted_headers: ['x-forwarded-for', 'x-forwarded-proto']\n"}, false},
		{"AT-02 trusted_proxies alone", "partial", "trusted_proxies=10.0.0.0/8",
			map[string]string{frameworkYAML: "framework:\n  trusted_proxies: '10.0.0.0/8'\n"}, false},
		{"AT-03 remoteip enabled with no RemoteIPHeader", "partial", "remoteip=enabled",
			map[string]string{"Dockerfile": base + "RUN a2enmod rewrite remoteip\n"}, false},
		{"AT-04 RemoteIPHeader and RemoteIPTrustedProxy", "configured", "remoteip=enabled; RemoteIPHeader=X-Forwarded-For; RemoteIPTrustedProxy=10.0.0.0/8",
			map[string]string{"Dockerfile": base + "RUN a2enmod remoteip\n", "deploy/site.conf": conf + "RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 10.0.0.0/8\n"}, false},
		{"AT-04 nginx real_ip_header and set_real_ip_from", "configured", "real_ip_header=X-Forwarded-For; set_real_ip_from=10.0.0.0/8",
			map[string]string{"deploy/site.conf": "server {\n  set_real_ip_from 10.0.0.0/8; real_ip_header X-Forwarded-For;\n}\n"}, false},
		{"AT-05 framework.yaml cannot be parsed", "unread", "", map[string]string{frameworkYAML: "framework: [\n"}, true},
		{"AT-05 no file that could state the trust", "unread", "", map[string]string{frameworkYAML: removed, "deploy/site.conf": removed}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := phpAnalyze(t, overlayFixture(t, symfonyConfiguration, tt.overlay), "")
			var guards []analysis.AuthorizationGuard
			for _, u := range r.Uses {
				if u.Authorization == nil {
					continue
				}
				for _, g := range u.Authorization.Guards {
					if g.Kind == analysis.GuardAddress {
						guards = append(guards, g)
					}
				}
			}
			if len(guards) == 0 {
				t.Fatal("no address guard recorded")
			}
			for _, g := range guards {
				if g.AddressTrust == nil || g.AddressTrust.Status != tt.status || g.AddressTrust.Evidence.Text != tt.text {
					t.Fatalf("address_trust %+v, want %s %q", g.AddressTrust, tt.status, tt.text)
				}
				if got := slices.Contains(gapKinds(g.Gaps), "address_trust_configuration_unread"); got != tt.gap {
					t.Fatalf("gap present %v, want %v", got, tt.gap)
				}
			}
		})
	}
}

func mustRead(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

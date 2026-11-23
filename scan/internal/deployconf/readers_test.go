package deployconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReaders(t *testing.T) {
	t.Run("RD-01", func(t *testing.T) {
		got, gaps := Apache("site.conf", fixture(t, "rd01.conf"))
		want := []Directive{{File: "site.conf", Line: 2, Name: "Options", Values: []string{"+Indexes", "+FollowSymLinks"}, Scope: "/srv/site/web", ScopeLine: 1, Effective: []string{"Indexes", "FollowSymLinks"}}}
		if len(gaps) != 0 || !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v gaps %v", got, gaps)
		}
	})
	t.Run("RD-02", func(t *testing.T) {
		got, _ := Apache("site.conf", fixture(t, "rd02.conf"))
		if len(got) != 2 || Indexes(got[0].Effective) || len(got[1].Effective) != 0 {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-03", func(t *testing.T) {
		got, _ := Apache("site.conf", fixture(t, "rd03.conf"))
		if len(got) != 2 || got[0].Scope != "/srv/site" || !Indexes(got[0].Effective) || got[1].Scope != "/srv/site/private" || got[1].ScopeLine != 3 || Indexes(got[1].Effective) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-04", func(t *testing.T) {
		got, _ := Nginx("site.conf", fixture(t, "rd04.conf"))
		want := Directive{File: "site.conf", Line: 4, Name: "autoindex", Values: []string{"on"}, Scope: "location /files", ScopeLine: 3, Dir: "/srv/site/web/files"}
		if len(got) != 2 || got[0].Name != "root" || !reflect.DeepEqual(got[1], want) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-05", func(t *testing.T) {
		img := Dockerfile("Dockerfile", fixture(t, "rd05.dockerfile"), nil)
		wantEnv := []PathMapping{{Dst: "/srv/site/.env.local", Src: "deploy/env.prod", Line: 4}}
		if p, ok := img.ProjectPath("/srv/site/web"); !ok || p != "web" || !reflect.DeepEqual(img.EnvFiles, wantEnv) {
			t.Fatalf("%+v", img)
		}
		if p, ok := img.ProjectPath("/srv/site/.env.local"); !ok || p != "deploy/env.prod" {
			t.Fatalf("later file COPY must win: %q", p)
		}
	})
	t.Run("RD-06", func(t *testing.T) {
		img := Dockerfile("Dockerfile", fixture(t, "rd06.dockerfile"), nil)
		want := []Ownership{{File: "Dockerfile", User: "web", Path: "/srv/site/tools", Line: 3, Recursive: true}}
		if !reflect.DeepEqual(img.Owners, want) {
			t.Fatalf("%+v", img.Owners)
		}
	})
	t.Run("RD-07", func(t *testing.T) {
		img := Dockerfile("Dockerfile", fixture(t, "rd07.dockerfile"), nil)
		want := []ScheduleLine{{File: "Dockerfile", User: "root", Command: "cd /srv/site && sh tools/tick.sh", Line: 2, System: true}}
		if !reflect.DeepEqual(img.Schedules, want) {
			t.Fatalf("%+v", img.Schedules)
		}
	})
	t.Run("RD-08", func(t *testing.T) {
		img := Dockerfile("Dockerfile", fixture(t, "rd08.dockerfile"), nil)
		if len(img.Gaps) != 1 || img.Gaps[0].Kind != "deploy_mapping_unresolved" || img.Gaps[0].Line != 2 || len(img.Paths) != 0 {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("RD-09", func(t *testing.T) {
		got := Cron("cron.d/site", fixture(t, "cron.d/rd09"), true)
		want := []ScheduleLine{{File: "cron.d/site", User: "root", Command: "/srv/site/tools/tick.sh", Line: 3, System: true}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-10", func(t *testing.T) {
		got := Cron("crontab", fixture(t, "rd10.cron"), false)
		if len(got) != 1 || got[0].User != "" || got[0].Command != "/srv/site/tools/tick.sh" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-11", func(t *testing.T) {
		got, _ := PHPIni("php.ini", fixture(t, "rd11.ini"))
		want := []Directive{
			{File: "php.ini", Line: 2, Name: "display_errors", Values: []string{"On"}},
			{File: "php.ini", Line: 3, Name: "session.cookie_httponly", Values: []string{"0"}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-12", func(t *testing.T) {
		got, _ := EnvKeys(".env", fixture(t, "rd12.env"))
		raw, _ := json.Marshal(got)
		want := map[string]EnvSetting{"APP_ENV": {"APP_ENV", "dev", 1}, "APP_DEBUG": {"APP_DEBUG", "1", 2}}
		if !reflect.DeepEqual(got, want) || strings.Contains(string(raw), "marker-secret-value") {
			t.Fatalf("%s", raw)
		}
	})
	t.Run("RD-13", func(t *testing.T) {
		got, _ := Apache("public/files/.htaccess", fixture(t, "rd13.htaccess"))
		if len(got) != 1 || got[0].Scope != "public/files" || !Indexes(got[0].Effective) {
			t.Fatalf("%+v", got)
		}
		if got, _ := Apache(".htaccess", fixture(t, "rd13.htaccess")); len(got) != 1 || got[0].Scope != "." {
			t.Fatalf("root .htaccess: %+v", got)
		}
	})
	t.Run("RD-14", func(t *testing.T) {
		big := []byte(strings.Repeat("a", MaxFile+1))
		for name, gaps := range map[string][]Gap{
			"apache": second(Apache("site.conf", big)), "nginx": second(Nginx("site.conf", big)),
			"ini": second(PHPIni("php.ini", big)), "env": envGaps(big), "docker": Dockerfile("Dockerfile", big, nil).Gaps,
		} {
			if len(gaps) != 1 || gaps[0].Kind != "config_file_unread" {
				t.Fatalf("%s: %+v", name, gaps)
			}
		}
	})
}

func second(_ []Directive, gaps []Gap) []Gap { return gaps }

func envGaps(src []byte) []Gap {
	_, gaps := EnvKeys(".env", src)
	return gaps
}

// TestEnvKeysKeepNothingElse covers the forms that could carry another
// variable's value into a kept key.
func TestEnvKeysKeepNothingElse(t *testing.T) {
	const marker = "s3cr3t-marker"
	for name, src := range map[string]string{
		"backslash continuation": "APP_ENV=dev\\\nAPP_SECRET=" + marker + "\nAPP_DEBUG=1\n",
		"value with spaces":      "APP_ENV=dev " + marker + "\n",
		"value with assignment":  "APP_ENV=dev;APP_SECRET=" + marker + "\n",
		"quoted sentence":        "APP_DEBUG=\"1 " + marker + "\"\n",
		"substitution":           "APP_ENV=${APP_SECRET:-" + marker + "}\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := EnvKeys(".env", []byte(src))
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), marker) || strings.Contains(string(raw), "SECRET") {
				t.Fatalf("leaked: %s", raw)
			}
		})
	}
	got, _ := EnvKeys(".env", []byte("# c\nexport APP_ENV=\"prod\" # live\nAPP_DEBUG=0\n"))
	if got["APP_ENV"] != (EnvSetting{"APP_ENV", "prod", 2}) || got["APP_DEBUG"].Line != 3 {
		t.Fatalf("%+v", got)
	}
}

func TestApacheOptions(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      [][]string
	}{
		{"relative merges with the scope's earlier Options", "<Directory /a>\nOptions Indexes\nOptions +FollowSymLinks\n</Directory>\n", [][]string{{"Indexes"}, {"Indexes", "FollowSymLinks"}}},
		{"names compare without case", "Options +indexes\n", [][]string{{"Indexes"}}},
		{"All includes Indexes", "Options All\n", [][]string{{"ExecCGI", "FollowSymLinks", "Includes", "Indexes", "SymLinksIfOwnerMatch"}}},
		{"All minus Indexes", "Options All\nOptions -Indexes\n", [][]string{{"ExecCGI", "FollowSymLinks", "Includes", "Indexes", "SymLinksIfOwnerMatch"}, {"ExecCGI", "FollowSymLinks", "Includes", "SymLinksIfOwnerMatch"}}},
		{"a bare list replaces the inherited one", "Options Indexes\n<Directory /a>\nOptions FollowSymLinks\n</Directory>\n", [][]string{{"Indexes"}, {"FollowSymLinks"}}},
		{"a relative list inherits", "Options Indexes\n<Directory /a>\nOptions +FollowSymLinks\n</Directory>\n", [][]string{{"Indexes"}, {"Indexes", "FollowSymLinks"}}},
		{"a conditional container keeps the scope", "<Directory /a>\n<IfModule mod_autoindex.c>\nOptions +Indexes\n</IfModule>\nOptions +ExecCGI\n</Directory>\n", [][]string{{"Indexes"}, {"Indexes", "ExecCGI"}}},
		{"a Location container is not a directory scope", "<Location /x>\nOptions +Indexes\n</Location>\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Apache("site.conf", []byte(tt.src))
			var lists [][]string
			for _, d := range got {
				lists = append(lists, d.Effective)
			}
			if !reflect.DeepEqual(lists, tt.want) {
				t.Fatalf("%v, want %v", lists, tt.want)
			}
		})
	}
}

func TestNginxStatements(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      []Directive
	}{
		{"two statements on one line", "root /var/www; autoindex on;\n", []Directive{
			{File: "n.conf", Line: 1, Name: "root", Values: []string{"/var/www"}, Dir: "/var/www"},
			{File: "n.conf", Line: 1, Name: "autoindex", Values: []string{"on"}, Dir: "/var/www"}}},
		{"a one-line location does not leak its scope", "server {\nroot /srv;\nlocation /a { autoindex on; }\nautoindex off;\n}\n", []Directive{
			{File: "n.conf", Line: 2, Name: "root", Values: []string{"/srv"}, Dir: "/srv"},
			{File: "n.conf", Line: 3, Name: "autoindex", Values: []string{"on"}, Scope: "location /a", ScopeLine: 3, Dir: "/srv/a"},
			{File: "n.conf", Line: 4, Name: "autoindex", Values: []string{"off"}, Dir: "/srv"}}},
		{"a nested block's close keeps the outer location", "location /a {\nif ($x) { set $y 1; }\nautoindex on;\n}\n", []Directive{
			{File: "n.conf", Line: 3, Name: "autoindex", Values: []string{"on"}, Scope: "location /a", ScopeLine: 1}}},
		{"a root written after the directive still applies", "location /a {\nautoindex on;\n}\nroot /srv;\n", []Directive{
			{File: "n.conf", Line: 2, Name: "autoindex", Values: []string{"on"}, Scope: "location /a", ScopeLine: 1, Dir: "/srv/a"},
			{File: "n.conf", Line: 4, Name: "root", Values: []string{"/srv"}, Dir: "/srv"}}},
		{"a pattern location has no directory", "root /srv;\nlocation ~ \\.php$ {\nautoindex on;\n}\n", []Directive{
			{File: "n.conf", Line: 1, Name: "root", Values: []string{"/srv"}, Dir: "/srv"},
			{File: "n.conf", Line: 3, Name: "autoindex", Values: []string{"on"}, Scope: "location ~ \\.php$", ScopeLine: 2}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := Nginx("n.conf", []byte(tt.src)); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestDockerfileShapes(t *testing.T) {
	dirs := func(p string) bool { return p == "bin" }
	t.Run("semicolons separate RUN commands", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nRUN set -eux; chown -R web /srv/site; \\\n    chmod 777 /srv/site/a /srv/site/b\n"), nil)
		want := []Ownership{
			{File: "Dockerfile", User: "web", Path: "/srv/site", Line: 2, Recursive: true},
			{File: "Dockerfile", Mode: "777", Path: "/srv/site/a", Line: 3},
			{File: "Dockerfile", Mode: "777", Path: "/srv/site/b", Line: 3},
		}
		if !reflect.DeepEqual(img.Owners, want) {
			t.Fatalf("%+v", img.Owners)
		}
	})
	t.Run("each chown has its own line and a trailing -R counts", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nRUN chown a /x && \\\n    chown b /y -R\n"), nil)
		if len(img.Owners) != 2 || img.Owners[0].Line != 2 || img.Owners[1].Line != 3 || !img.Owners[1].Recursive || img.Owners[0].Recursive {
			t.Fatalf("%+v", img.Owners)
		}
	})
	t.Run("COPY into a directory keeps the base name", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nCOPY .env.prod /srv/app/\nCOPY a.conf b.conf /etc/nginx/conf.d/\nCOPY bin /srv/app/bin/\n"), dirs)
		want := []PathMapping{
			{Dst: "/srv/app/.env.prod", Src: ".env.prod", Line: 2},
			{Dst: "/etc/nginx/conf.d/a.conf", Src: "a.conf", Line: 3},
			{Dst: "/etc/nginx/conf.d/b.conf", Src: "b.conf", Line: 3},
			{Dst: "/srv/app/bin", Src: "bin", Line: 4},
		}
		if !reflect.DeepEqual(img.Paths, want) || len(img.EnvFiles) != 1 {
			t.Fatalf("%+v", img.Paths)
		}
		if line, ok := img.Installed("b.conf"); !ok || line != 3 {
			t.Fatalf("installed %d %v", line, ok)
		}
		if _, ok := img.Installed(".env.prod"); ok {
			t.Fatal("an application file is not installed server configuration")
		}
	})
	t.Run("a source outside the build context is not mapped", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nCOPY ../outside.env /app/.env\n"), nil)
		if len(img.Paths) != 0 || len(img.EnvFiles) != 0 || len(img.Gaps) != 1 {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("only the last stage is deployed", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM a AS build\nCOPY . /src\nRUN chown web /src/x\nFROM b\nCOPY --from=build /src /app\n"), nil)
		if len(img.Paths) != 0 || len(img.Owners) != 0 || len(img.Gaps) != 1 {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("the JSON form of COPY", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nCOPY --chown=web:web [\"my app\", \"/srv/app\"]\n"), nil)
		if len(img.Paths) != 1 || img.Paths[0].Src != "my app" || len(img.Owners) != 1 || img.Owners[0].User != "web" {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("crontab install and modules", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("FROM x\nWORKDIR /srv\nUSER web\nRUN a2enmod rewrite remoteip && crontab deploy/jobs\n"), nil)
		if len(img.Modules) != 2 || img.Modules[1].Values[0] != "remoteip" || len(img.CronInstall) != 1 || img.CronInstall[0].User != "web" || img.CronInstall[0].Path != "/srv/deploy/jobs" {
			t.Fatalf("%+v", img)
		}
	})
}

func TestCronForms(t *testing.T) {
	got := Cron("jobs", []byte("@daily root /srv/a.sh\n@reboot /srv/b.sh\n0 1 * * * web cd /srv; php x # nightly\n"), true)
	want := []ScheduleLine{
		{File: "jobs", User: "root", Command: "/srv/a.sh", Line: 1, System: true},
		{File: "jobs", User: "web", Command: "cd /srv; php x # nightly", Line: 3, System: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestGroupOrOtherWrite(t *testing.T) {
	for mode, want := range map[string]bool{
		"777": true, "0775": true, "0644": false, "755": false, "o+w": true, "g+w": true, "a+rwx": true,
		"o+rwx": true, "+w": true, "u+w": false, "+x": false, "o-w": false, "u=rwx,go=rx": false, "u=rwx,go=rwx": true, "": false,
	} {
		if got := GroupOrOtherWrite(mode); got != want {
			t.Errorf("%q: %v, want %v", mode, got, want)
		}
	}
}

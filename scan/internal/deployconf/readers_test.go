package deployconf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReaders(t *testing.T) {
	t.Run("RD-01", func(t *testing.T) {
		got, gaps := Apache("site.conf", []byte("<Directory /srv/site/web>\nOptions +Indexes +FollowSymLinks\n</Directory>\n"))
		if len(gaps) != 0 || len(got) != 1 || got[0].Name != "Options" || got[0].Scope != "/srv/site/web" || got[0].Line != 2 || !Indexes(got[0].Effective) {
			t.Fatalf("%+v gaps %v", got, gaps)
		}
		if strings.Join(got[0].Values, " ") != "+Indexes +FollowSymLinks" {
			t.Fatalf("values %v", got[0].Values)
		}
	})
	t.Run("RD-02", func(t *testing.T) {
		got, _ := Apache("site.conf", []byte("Options -Indexes\nOptions None\n"))
		if len(got) != 2 || Indexes(got[0].Effective) || Indexes(got[1].Effective) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-03", func(t *testing.T) {
		src := "<Directory /srv/site>\nOptions +Indexes\n<Directory /srv/site/private>\nOptions -Indexes\n</Directory>\n</Directory>\n"
		got, _ := Apache("site.conf", []byte(src))
		if len(got) != 2 || got[0].Scope != "/srv/site" || !Indexes(got[0].Effective) || got[1].Scope != "/srv/site/private" || Indexes(got[1].Effective) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-04", func(t *testing.T) {
		got, _ := Nginx("site.conf", []byte("location /files {\nautoindex on;\n}\n"))
		if len(got) != 1 || got[0].Name != "autoindex" || got[0].Values[0] != "on" || got[0].Scope != "location /files" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-05", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("WORKDIR /srv/site\nCOPY . /srv/site\nCOPY deploy/env.prod /srv/site/.env.local\n"))
		if img.PathMap["/srv/site"] != "." || len(img.EnvFiles) != 1 || img.EnvFiles[0].Src != "deploy/env.prod" || img.EnvFiles[0].Dst != "/srv/site/.env.local" {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("RD-06", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("RUN a && \\\n    chown -R web:web /srv/site/tools\n"))
		if len(img.Owners) != 1 || img.Owners[0].User != "web" || img.Owners[0].Path != "/srv/site/tools" || !img.Owners[0].Recursive || img.Owners[0].Line != 2 {
			t.Fatalf("%+v", img.Owners)
		}
	})
	t.Run("RD-07", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("RUN echo \"*/5 * * * * root cd /srv/site && sh tools/tick.sh\" > /etc/cron.d/site\n"))
		if len(img.Schedules) != 1 || img.Schedules[0].User != "root" || !strings.Contains(img.Schedules[0].Command, "sh tools/tick.sh") {
			t.Fatalf("%+v", img.Schedules)
		}
	})
	t.Run("RD-08", func(t *testing.T) {
		img := Dockerfile("Dockerfile", []byte("COPY ${SRC} /srv/site\n"))
		if len(img.Gaps) != 1 || img.Gaps[0].Kind != "deploy_mapping_unresolved" {
			t.Fatalf("%+v", img)
		}
	})
	t.Run("RD-09", func(t *testing.T) {
		src := "# nightly\nMAILTO=ops@example.test\n*/5 * * * * root /srv/site/tools/tick.sh\n"
		got := Cron("cron.d/site", []byte(src), true)
		if len(got) != 1 || got[0].User != "root" || got[0].Command != "/srv/site/tools/tick.sh" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-10", func(t *testing.T) {
		got := Cron("crontab", []byte("*/5 * * * * /srv/site/tools/tick.sh\n"), false)
		if len(got) != 1 || got[0].User != "" || !strings.Contains(got[0].Command, "tick.sh") {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-11", func(t *testing.T) {
		got, _ := PHPIni("php.ini", []byte("display_errors = On\nsession.cookie_httponly = 0\n"))
		if len(got) != 2 || got[0].Name != "display_errors" || got[1].Name != "session.cookie_httponly" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-12", func(t *testing.T) {
		secret := "postgres://marker-secret-value"
		got, _ := EnvKeys(".env", []byte("APP_ENV=dev\nAPP_DEBUG=1\nDATABASE_URL="+secret+"\n"))
		raw, _ := json.Marshal(got)
		if got["APP_ENV"] != "dev" || got["APP_DEBUG"] != "1" || strings.Contains(string(raw), secret) || len(got) != 2 {
			t.Fatalf("%v %s", got, raw)
		}
	})
	t.Run("RD-13", func(t *testing.T) {
		got, _ := Apache("public/files/.htaccess", []byte("Options +Indexes\n"))
		if len(got) != 1 || got[0].Scope != "public/files" || !Indexes(got[0].Effective) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("RD-14", func(t *testing.T) {
		_, gaps := Apache("site.conf", []byte(strings.Repeat("a", MaxFile+1)))
		if len(gaps) != 1 || gaps[0].Kind != "config_file_unread" {
			t.Fatalf("%+v", gaps)
		}
	})
}

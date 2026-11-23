package langphp

import (
	"path"
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
)

// scheduledJob is one cron line with the ownership instructions that can
// apply to the files it runs.
type scheduledJob struct {
	deployconf.ScheduleLine
	owners []deployconf.Ownership
	scope  analysis.Evidence
}

// chainLink is one file a scheduled command runs: the place that names it
// and its path in the container.
type chainLink struct {
	file, name, container string
	line                  int
}

func (s *phpSet) emitSchedules(out *analysis.AnalysisReport, v *deployView) {
	for _, job := range s.scheduledJobs(v) {
		if job.User == "" {
			job.User = "root"
		}
		link, own, ok := v.writableLink(job)
		if !ok {
			continue
		}
		ownership := own.User + " owns " + own.Path + ", not the schedule user " + job.User
		if own.User == "" {
			ownership = "mode " + own.Mode + " lets users other than " + job.User + " write " + own.Path
		}
		chainFile, chainLine := link.file, link.line
		if chainFile == "" {
			chainFile, chainLine = job.File, job.Line
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckScheduledPrivileged, Value: job.User + " " + job.Command, Scope: "deployment",
			Setting: s.lineEvidence(job.File, "setting", job.User+" runs "+job.Command, job.Line),
			Joined: []analysis.Evidence{
				s.lineEvidence(job.File, "config_installed", "schedule is in the deployment file", job.Line),
				s.lineEvidence(job.File, "schedule", job.User+" runs "+job.Command, job.Line),
				s.lineEvidence(chainFile, "chain", "the scheduled script runs "+link.name, chainLine),
				s.lineEvidence(own.File, "ownership", ownership, own.Line),
			},
		}
		s.emitConfig(out, v.root, facts, job.scope, nil)
	}
}

// scheduledJobs lists the cron lines of the project: the text a Dockerfile
// writes into /etc/cron.d, then each cron file. A file installed with
// `crontab <file>` is a user crontab and runs as the user in force at that
// instruction. Any other cron file has the system form with a user field.
func (s *phpSet) scheduledJobs(v *deployView) []scheduledJob {
	var jobs []scheduledJob
	var owners []deployconf.Ownership
	for _, img := range v.images {
		owners = append(owners, img.Owners...)
		scope := s.lineEvidence(img.File, "scope", "image built from "+img.File, img.FromLine)
		for _, line := range img.Schedules {
			jobs = append(jobs, scheduledJob{ScheduleLine: line, owners: img.Owners, scope: scope})
		}
	}
	for _, file := range s.deployFiles {
		base := path.Base(file)
		if !underRoot(v.root, file) || (base != "crontab" && !strings.HasSuffix(base, ".cron") && path.Base(path.Dir(file)) != "cron.d") {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		user, scope := "", s.lineEvidence(file, "scope", "cron file "+file, 1)
		installed := false
		for _, img := range v.images {
			for _, inst := range img.CronInstall {
				if mapped, ok := v.projectPath(inst.Path); ok && mapped == file {
					installed, user = true, inst.User
					scope = s.lineEvidence(img.File, "scope", "crontab "+inst.Path+" installed for "+inst.User, inst.Line)
				}
			}
		}
		for _, line := range deployconf.Cron(file, raw, !installed) {
			if installed {
				line.User = user
			}
			jobs = append(jobs, scheduledJob{ScheduleLine: line, owners: owners, scope: scope})
		}
	}
	return jobs
}

// writableLink returns the first file of the job's execution chain that a
// user other than the schedule user can rewrite. The last chown that covers
// a file names its owner. A chmod counts when it gives group or other write.
func (v *deployView) writableLink(job scheduledJob) (chainLink, deployconf.Ownership, bool) {
	for _, link := range v.chain(job.Command) {
		var owner, mode *deployconf.Ownership
		for i, own := range job.owners {
			if own.Path != link.container && !(own.Recursive && strings.HasPrefix(link.container, strings.TrimRight(own.Path, "/")+"/")) {
				continue
			}
			switch {
			case own.User != "":
				owner = &job.owners[i]
			case deployconf.GroupOrOtherWrite(own.Mode):
				mode = &job.owners[i]
			case strings.Trim(own.Mode, "01234567") == "":
				mode = nil
			}
		}
		if owner != nil && owner.User != job.User {
			return link, *owner, true
		}
		if mode != nil {
			return link, *mode, true
		}
	}
	return chainLink{}, deployconf.Ownership{}, false
}

var pathWord = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)

// looksPath reports a command word that is a literal path.
func looksPath(tok string) bool {
	return pathWord.MatchString(tok) && !strings.HasPrefix(tok, "-") && (strings.Contains(tok, "/") || strings.HasPrefix(tok, "."))
}

// chain lists the files a command line runs: its program and literal path
// arguments and, for a project script it runs, the same for each line of
// that script, one level deep. A leading `cd <dir>` sets the directory that
// relative paths resolve against, in the line and in the script. A relative
// path with no such directory is not resolved.
func (v *deployView) chain(command string) []chainLink {
	cwd := ""
	resolve := func(tok string) (string, bool) {
		if path.IsAbs(tok) {
			return path.Clean(tok), true
		}
		if cwd == "" {
			return "", false
		}
		return path.Join(cwd, tok), true
	}
	var links []chainLink
	for _, part := range strings.Split(strings.ReplaceAll(command, ";", "&&"), "&&") {
		toks := strings.Fields(part)
		if len(toks) > 1 && toks[0] == "cd" {
			if dir, ok := resolve(toks[1]); ok {
				cwd = dir
			}
			continue
		}
		for i, tok := range toks {
			container, ok := resolve(tok)
			if !looksPath(tok) || !ok {
				continue
			}
			project, mapped := v.projectPath(container)
			link := chainLink{name: tok, container: container}
			if mapped {
				link.file, link.line = project, 1
			}
			links = append(links, link)
			script := i == 0 || toks[i-1] == "bash" || toks[i-1] == "sh" || toks[i-1] == "php" || strings.HasPrefix(tok, "./")
			raw, ok := v.set.readAllow(project)
			if !mapped || !script || !ok {
				continue
			}
			for n, line := range strings.Split(string(raw), "\n") {
				if line = strings.TrimSpace(line); strings.HasPrefix(line, "#") {
					continue
				}
				for _, word := range strings.Fields(line) {
					if target, ok := resolve(word); ok && looksPath(word) {
						links = append(links, chainLink{file: project, line: n + 1, name: word, container: target})
					}
				}
			}
		}
	}
	return links
}

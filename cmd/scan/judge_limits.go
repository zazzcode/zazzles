package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/internal/judge"
)

type judgeLimitFlags struct{ rpm, tpm *string }

func addJudgeLimitFlags(fs *flag.FlagSet) judgeLimitFlags {
	return judgeLimitFlags{
		fs.String("judge-rpm", "", "shared requests per rolling minute; defaults to JUDGE_RPM; 0 disables pacing"),
		fs.String("judge-tpm", "", "shared estimated input tokens per rolling minute; defaults to JUDGE_TPM; 0 disables pacing"),
	}
}
func (f judgeLimitFlags) resolve(fs *flag.FlagSet, getenv func(string) string) (judge.Limits, int, error) {
	var cfg judge.Limits
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	value := func(flagName, envName, raw string) string {
		if explicit[flagName] {
			return raw
		}
		return strings.TrimSpace(getenv(envName))
	}
	integer := func(flagName, envName, raw string) (int64, error) {
		s := value(flagName, envName, raw)
		if s == "" && !explicit[flagName] {
			return 0, nil
		}
		v, e := strconv.ParseInt(s, 10, 64)
		if e != nil || v < 0 {
			return 0, fmt.Errorf("--%s requires a nonnegative integer", flagName)
		}
		return v, nil
	}
	rpm, err := integer("judge-rpm", "JUDGE_RPM", *f.rpm)
	if err != nil || rpm > int64(^uint(0)>>1) {
		return cfg, 0, fmt.Errorf("--judge-rpm requires a bounded nonnegative integer")
	}
	cfg.RPM = int(rpm)
	if cfg.TPM, err = integer("judge-tpm", "JUDGE_TPM", *f.tpm); err != nil {
		return cfg, 0, err
	}
	limit := 10
	if raw := getenv("JUDGE_LIMIT"); !explicit["judge-limit"] && raw != "" {
		v, e := strconv.Atoi(strings.TrimSpace(raw))
		if e != nil || v < 1 {
			return cfg, 0, fmt.Errorf("JUDGE_LIMIT requires a positive integer")
		}
		limit = v
	}
	if explicit["judge-limit"] {
		v, e := strconv.Atoi(fs.Lookup("judge-limit").Value.String())
		if e != nil || v < 1 {
			return cfg, 0, fmt.Errorf("--judge-limit requires a positive integer")
		}
		limit = v
	}
	return cfg, limit, nil
}

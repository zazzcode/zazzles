package cli

import (
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/judge"
)

type judgeLimitFlags struct{ rpm, tpm, concurrency *string }

// defaultJudgeConcurrency caps in-flight assessment requests when neither the
// flag nor JUDGE_CONCURRENCY is set. RPM and TPM pacing still bound throughput.
const defaultJudgeConcurrency = 4

// noJudgeLimit is the default cap: every candidate is judged unless the user
// sets --judge-limit or JUDGE_LIMIT. Spending limits belong in the provider account.
const noJudgeLimit = math.MaxInt32

// judgeRuntime is the resolved scan-local judge pacing and concurrency.
type judgeRuntime struct {
	limits      judge.Limits
	concurrency int
}

func addJudgeLimitFlags(fs *flag.FlagSet) judgeLimitFlags {
	return judgeLimitFlags{
		fs.String("judge-rpm", "", "shared requests per rolling minute; defaults to JUDGE_RPM; 0 disables pacing"),
		fs.String("judge-tpm", "", "shared estimated input tokens per rolling minute; defaults to JUDGE_TPM; 0 disables pacing"),
		fs.String("judge-concurrency", "", fmt.Sprintf("maximum assessment requests in flight; defaults to JUDGE_CONCURRENCY, else %d; 1 is serial", defaultJudgeConcurrency)),
	}
}
func (f judgeLimitFlags) resolve(fs *flag.FlagSet, getenv func(string) string) (judgeRuntime, int, error) {
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
		return judgeRuntime{}, 0, fmt.Errorf("--judge-rpm requires a bounded nonnegative integer")
	}
	cfg.RPM = int(rpm)
	if cfg.TPM, err = integer("judge-tpm", "JUDGE_TPM", *f.tpm); err != nil {
		return judgeRuntime{}, 0, err
	}
	concurrency := defaultJudgeConcurrency
	if s := value("judge-concurrency", "JUDGE_CONCURRENCY", *f.concurrency); s != "" || explicit["judge-concurrency"] {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 {
			return judgeRuntime{}, 0, fmt.Errorf("--judge-concurrency requires a positive integer")
		}
		concurrency = v
	}
	limit := noJudgeLimit
	if raw := getenv("JUDGE_LIMIT"); !explicit["judge-limit"] && raw != "" {
		v, e := strconv.Atoi(strings.TrimSpace(raw))
		if e != nil || v < 1 {
			return judgeRuntime{}, 0, fmt.Errorf("JUDGE_LIMIT requires a positive integer")
		}
		limit = v
	}
	if explicit["judge-limit"] {
		v, e := strconv.Atoi(fs.Lookup("judge-limit").Value.String())
		if e != nil || v < 1 {
			return judgeRuntime{}, 0, fmt.Errorf("--judge-limit requires a positive integer")
		}
		limit = v
	}
	return judgeRuntime{cfg, concurrency}, limit, nil
}

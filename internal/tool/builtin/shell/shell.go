// Package shell is tyto's OPERATOR CONSOLE tool: it runs commands on the Kali
// host tyto itself runs on — the operator's own toolbox — NOT against a client
// target. It exists so the chat assistant can answer "is rockyou.txt in the
// wordlists?", "what version is nmap?", "grep seclists for admin" by actually
// LOOKING, instead of guessing.
//
// Two tiers, decided by the deterministic Classify function — the SINGLE source
// of truth the Scope Guard's RiskClassifier and the chat console both consult,
// so the read-only-vs-arbitrary call can never drift between them and the model
// can never self-promote a command past it:
//
//   - READ-ONLY toolbox introspection — an allowlist of non-mutating binaries,
//     no redirects, no command/process substitution, no backgrounding:
//     RiskLow, runs immediately.
//   - anything else — arbitrary commands: RiskHigh. The chat console makes the
//     operator confirm before it runs; the guard makes it require an authorized
//     grant when aimed at a client target.
package shell

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// LocalTarget is the reserved target value for commands that run on tyto's own
// operating host rather than a client asset. The chat console uses it so audit
// records show the command hit the operator box, not the engagement scope.
const LocalTarget = "localhost"

// readOnlyBins is the allowlist of binaries that only READ — they enumerate the
// toolbox or stream file contents and cannot mutate state. Anything not here is
// treated as arbitrary (RiskHigh) and falls to the confirmation path. Notable
// exclusions kept deliberately OUT: sed (writes with -i), xargs/find -exec
// (run arbitrary children), tee/dd/cp/mv/rm (write), sudo/su (escalate).
var readOnlyBins = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "tac": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true,
	"find": true, "locate": true, "which": true, "whereis": true, "type": true,
	"wc": true, "file": true, "stat": true, "du": true, "df": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "comm": true,
	"nl": true, "column": true, "look": true,
	"echo": true, "printf": true, "pwd": true, "basename": true, "dirname": true,
	"realpath": true, "readlink": true, "tree": true, "seq": true,
	"sha1sum": true, "sha256sum": true, "md5sum": true, "base64": true,
	"strings": true, "xxd": true, "hexdump": true, "od": true,
	"diff": true, "cmp": true, "env": true, "printenv": true,
	"date": true, "uname": true, "whoami": true, "id": true, "hostname": true,
	"uptime": true, "free": true, "lsblk": true,
}

// versionFlags are the only args tolerated for a NON-allowlisted binary: asking
// a tool to print its version/help is read-only regardless of the tool, so
// "nmap --version" classifies low without putting nmap on the allowlist.
var versionFlags = map[string]bool{
	"--version": true, "-version": true, "-V": true,
	"--help": true, "-h": true, "help": true, "version": true,
}

// IsReadOnly reports whether cmd is confined to the read-only toolbox-inspection
// tier. It is conservative and fails CLOSED: anything it does not positively
// recognize as safe returns false (→ arbitrary tier → operator confirmation).
func IsReadOnly(cmd string) bool {
	c := strings.TrimSpace(cmd)
	if c == "" {
		return false
	}
	// Reject shell constructs that can smuggle execution or writes regardless of
	// which binary leads the line.
	for _, bad := range []string{"$(", "`", "<(", ">(", ">", "${"} {
		if strings.Contains(c, bad) {
			return false
		}
	}
	// Split into pipeline/chain segments; every segment's leading binary must pass.
	// Normalize the multi-char separators to a single delimiter first.
	norm := c
	for _, sep := range []string{"&&", "||", ";", "|"} {
		norm = strings.ReplaceAll(norm, sep, "\x00")
	}
	for _, seg := range strings.Split(norm, "\x00") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.ContainsAny(seg, "&") { // leftover & = backgrounding
			return false
		}
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			return false
		}
		bin := fields[0]
		if i := strings.LastIndex(bin, "/"); i >= 0 { // /usr/bin/grep -> grep
			bin = bin[i+1:]
		}
		if readOnlyBins[bin] {
			// Allowlisted, but a few binaries have flags that WRITE or EXEC — those
			// drop the whole line to the arbitrary tier.
			if hasDangerousFlag(bin, fields[1:]) {
				return false
			}
			continue
		}
		// Not allowlisted: tolerate only a bare --version/--help probe.
		if !onlyVersionFlags(fields[1:]) {
			return false
		}
	}
	return true
}

// hasDangerousFlag reports whether an otherwise read-only binary was handed a
// flag that lets it execute or write to an arbitrary path.
func hasDangerousFlag(bin string, args []string) bool {
	switch bin {
	case "find":
		for _, a := range args {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete",
				"-fprint", "-fprint0", "-fprintf", "-fls":
				return true
			}
		}
	case "sort":
		for _, a := range args {
			if a == "-o" || strings.HasPrefix(a, "-o") && len(a) > 2 || strings.HasPrefix(a, "--output") {
				return true
			}
		}
	}
	return false
}

func onlyVersionFlags(args []string) bool {
	if len(args) == 0 {
		return false // a bare unknown binary with no args is not provably read-only
	}
	for _, a := range args {
		if !versionFlags[a] {
			return false
		}
	}
	return true
}

// Classify is the guard.RiskClassifier hook for this tool: read-only commands
// stay at the tool's RiskLow floor, everything else is RiskHigh.
func Classify(command string) action.RiskLevel {
	if IsReadOnly(command) {
		return action.RiskLow
	}
	return action.RiskHigh
}

// Tool runs operator commands on tyto's own host.
type Tool struct{}

// New constructs the shell tool.
func New() *Tool { return &Tool{} }

func (t *Tool) Name() string { return "shell" }

// Category is recon: the read-only floor. The per-param classifier raises an
// arbitrary command to RiskHigh, which is where the real gating happens.
func (t *Tool) Category() action.Category { return action.CategoryRecon }

// MaxRisk is the LOW floor; guard takes max(floor, Classify), so a read-only
// command stays low and an arbitrary one is lifted to high by the classifier.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// Execute runs Params["command"] on the local host via the operator's shell,
// bounded by ctx and the adapter's output cap. No target traffic is implied —
// this is the operator's own toolbox.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	cmd := strings.TrimSpace(a.Params["command"])
	if cmd == "" {
		res.Err = "no command provided"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	shellBin := strings.TrimSpace(os.Getenv("TYTO_SHELL"))
	if shellBin == "" {
		shellBin = "bash"
	}
	bin := adapter.Detect(shellBin, "sh")
	if bin == "" {
		res.Findings = []state.Finding{adapter.Missing("shell", LocalTarget, "a POSIX shell (bash/sh) is required on the operator host")}
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	out, err := adapter.Run(ctx, bin, []string{"-lc", cmd}, adapter.DefaultMaxOutput)
	res.Output = out
	res.Success = err == nil
	if err != nil {
		res.Err = err.Error()
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

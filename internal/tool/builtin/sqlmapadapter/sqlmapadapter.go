// Package sqlmapadapter drives sqlmap, the de-facto SQL-injection exploitation
// engine, as a tyto shell-out adapter. Where tyto's native sqliexploit tool
// performs a focused error/UNION-based extraction in pure Go, this adapter is
// the DEEP variant: it hands the target to sqlmap, which fingerprints the
// backend, confirms the injection technique, enumerates databases/users, and
// (on request) dumps real rows — the kind of exhaustive proof a pentest report
// leans on.
//
// It is an EXPLOITATION tool — CategoryExploit / RiskHigh — so the Scope Guard
// only ever runs it after confirming the target is in scope AND the engagement
// carries a cryptographic authorization grant for high-risk/exploit actions.
// sqlmap is invoked NON-INTERACTIVELY (--batch) and BOUNDED (level/risk 1, a
// fresh session, and the adapter's output cap) so it never blocks on a prompt
// nor runs away. When sqlmap isn't installed the adapter degrades gracefully to
// an Info finding rather than failing the run.
package sqlmapadapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool is the sqlmap adapter. It holds no state; sqlmap owns its own session.
type Tool struct{}

// New returns a ready sqlmap adapter.
func New() *Tool { return &Tool{} }

func (t *Tool) Name() string              { return "sqlmap" }
func (t *Tool) Category() action.Category { return action.CategoryExploit }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskHigh }

const (
	// maxOutput caps captured sqlmap output. sqlmap is chatty (banners, tables,
	// dumps) so 2 MiB gives ample room while still bounding memory.
	maxOutput = 2 << 20
	// evidenceMax / dumpMax bound the proof Evidence lengths per the spec.
	evidenceMax = 600
	dumpMax     = 600
	// sqlmapCVSS reflects full confidentiality/integrity/availability impact:
	// a confirmed, dumpable SQL injection is exploitable end-to-end.
	sqlmapCVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

// Execute detects sqlmap, runs it non-interactively and bounded against the
// target, and turns its text output into findings. It never returns a hard
// error for the normal paths: a missing binary or a non-injectable target both
// resolve to Success=true with an explanatory finding.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("sqlmap")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("sqlmap", a.Target, "apt install sqlmap"))
		res.Success = true
		res.Output = "sqlmap not installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	args := buildArgs(a)
	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings := parseSqlmap(out)
	// Stamp run-specific fields the pure parser can't know (ID/Target/time).
	for i := range findings {
		findings[i].ID = fmt.Sprintf("SQLMAP-%s-%d", a.ID, i+1)
		findings[i].Target = a.Target
		findings[i].Tool = t.Name()
		findings[i].FoundAt = time.Now().UTC()
	}
	res.Findings = findings

	confirmed := 0
	for _, f := range findings {
		if f.Severity == state.SeverityCritical {
			confirmed++
		}
	}

	res.Success = true
	if confirmed > 0 {
		res.Output = fmt.Sprintf("%s: sqlmap confirmed SQL injection (%d critical finding(s))", a.Target, confirmed)
	} else {
		res.Output = fmt.Sprintf("%s: sqlmap ran; no injection confirmed", a.Target)
	}
	if runErr != nil {
		// sqlmap commonly exits non-zero yet still prints useful results; record
		// the exit for audit but don't fail the action.
		res.Err = runErr.Error()
	}
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// buildArgs assembles the bounded, always-non-interactive sqlmap invocation:
//
//	sqlmap -u <target> --batch --banner --current-user --current-db --dbs
//	       --level 1 --risk 1 --flush-session
//
// --batch makes every prompt take its default (never blocks); --flush-session
// forces a clean run; --level/--risk 1 keep request volume minimal. POST is
// driven by Params["data"]; Params["dump"]=="true" adds --dump (optionally
// scoped to -T table / -D db).
func buildArgs(a action.Action) []string {
	args := []string{
		"-u", a.Target,
		"--batch",
		"--banner",
		"--current-user",
		"--current-db",
		"--dbs",
		"--level", "1",
		"--risk", "1",
		"--flush-session",
	}
	if data := a.Params["data"]; data != "" {
		args = append(args, "--data", data) // POST body
	}
	if a.Params["dump"] == "true" {
		args = append(args, "--dump")
		if tbl := a.Params["table"]; tbl != "" {
			args = append(args, "-T", tbl)
		}
		if db := a.Params["db"]; db != "" {
			args = append(args, "-D", db)
		}
	}
	return args
}

// parseSqlmap turns sqlmap's TEXT output into findings. It is a pure function of
// the output string (no run-specific ID/Target/time — the caller stamps those)
// so it is fully unit-testable against captured sqlmap runs.
//
// Signals (matched case-insensitively, line-based):
//   - "is vulnerable" / "parameter '...' is vulnerable" / "sqlmap identified the
//     following injection point" -> a Critical "SQL injection confirmed".
//   - "back-end DBMS: <x>" -> recorded and folded into the confirmed finding's
//     evidence (which DBMS was fingerprinted).
//   - "banner: '<x>'", "current user: '<x>'", "current database: '<x>'" ->
//     Critical "SQLi extraction: <field> = <value>" (the data IS the proof).
//   - "available databases [N]:" + following "[*] <name>" -> a finding listing
//     the databases.
//   - dumped table rows (lines inside a table block) under --dump -> a finding
//     with the rows.
//
// If nothing matched, a single Info "no injection confirmed" finding.
func parseSqlmap(out string) []state.Finding {
	lines := strings.Split(out, "\n")

	var findings []state.Finding
	var dbms string
	confirmed := false
	var confirmedEvidence []string

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)

		// Injection confirmation signals.
		if !confirmed && (strings.Contains(low, "is vulnerable") ||
			strings.Contains(low, "sqlmap identified the following injection point")) {
			confirmed = true
		}
		if confirmed && (strings.Contains(low, "is vulnerable") ||
			strings.Contains(low, "injection point")) {
			confirmedEvidence = append(confirmedEvidence, stripPrefix(line))
		}

		// Back-end DBMS fingerprint.
		if v := afterLabel(low, line, "back-end dbms:"); v != "" {
			dbms = v
		}
	}

	if confirmed {
		desc := "sqlmap confirmed an exploitable SQL injection in the target"
		ev := strings.Join(confirmedEvidence, "\n")
		if dbms != "" {
			desc += fmt.Sprintf(" (back-end DBMS: %s)", dbms)
			if ev != "" {
				ev += "\n"
			}
			ev += "back-end DBMS: " + dbms
		}
		findings = append(findings, state.Finding{
			Title:       "SQL injection confirmed by sqlmap",
			Severity:    state.SeverityCritical,
			Description: desc,
			Evidence:    truncate(ev, evidenceMax),
			CVSS:        sqlmapCVSS,
			Validated:   true,
		})
	}

	// Extracted single-value facts: banner / current user / current database.
	for _, ex := range []struct{ label, field string }{
		{"banner:", "banner"},
		{"current user:", "current user"},
		{"current database:", "current database"},
	} {
		if v := findQuotedAfter(lines, ex.label); v != "" {
			findings = append(findings, state.Finding{
				Title:    fmt.Sprintf("SQLi extraction: %s = %s", ex.field, v),
				Severity: state.SeverityCritical,
				Description: fmt.Sprintf("sqlmap extracted the %s from the target, proving exploitable "+
					"read access: %s = %q", ex.field, ex.field, v),
				Evidence:  truncate(v, evidenceMax),
				CVSS:      sqlmapCVSS,
				Validated: true,
			})
		}
	}

	// Available databases block: "available databases [N]:" then "[*] name".
	if dbs := parseDatabases(lines); len(dbs) > 0 {
		joined := strings.Join(dbs, ", ")
		findings = append(findings, state.Finding{
			Title:    fmt.Sprintf("SQLi extraction: %d database(s) enumerated", len(dbs)),
			Severity: state.SeverityCritical,
			Description: fmt.Sprintf("sqlmap enumerated the available databases, proving information_schema "+
				"read access: %s", joined),
			Evidence:  truncate(joined, evidenceMax),
			CVSS:      sqlmapCVSS,
			Validated: true,
		})
	}

	// Dumped table rows (only present under --dump).
	if rows := parseDumpRows(lines); rows != "" {
		findings = append(findings, state.Finding{
			Title:    "SQLi extraction: dumped table rows",
			Severity: state.SeverityCritical,
			Description: "sqlmap dumped rows from a target table, proving arbitrary data exfiltration " +
				"(rows truncated for the report)",
			Evidence:  truncate(rows, dumpMax),
			CVSS:      sqlmapCVSS,
			Validated: true,
		})
	}

	if len(findings) == 0 {
		findings = append(findings, state.Finding{
			Title:       "sqlmap ran; no injection confirmed",
			Severity:    state.SeverityInfo,
			Description: "sqlmap completed against the target but did not confirm a SQL injection point",
			Validated:   true,
		})
	}
	return findings
}

// afterLabel returns the trimmed remainder of line after a lowercase label, or
// "" if low doesn't contain it. low is the lowercased line; line preserves case
// for the returned value.
func afterLabel(low, line, label string) string {
	idx := strings.Index(low, label)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(line[idx+len(label):])
}

// findQuotedAfter scans lines for the first occurrence of label and returns the
// value quoted with single quotes after it, e.g. `banner: '5.7.41'` -> 5.7.41.
// Falls back to the unquoted remainder when no single-quoted value is present.
func findQuotedAfter(lines []string, label string) string {
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		low := strings.ToLower(line)
		rest := afterLabel(low, line, label)
		if rest == "" {
			continue
		}
		if q := betweenSingleQuotes(rest); q != "" {
			return q
		}
		return rest
	}
	return ""
}

// betweenSingleQuotes returns the substring between the first and last single
// quote in s, or "" if fewer than two are present.
func betweenSingleQuotes(s string) string {
	first := strings.IndexByte(s, '\'')
	last := strings.LastIndexByte(s, '\'')
	if first < 0 || last <= first {
		return ""
	}
	return s[first+1 : last]
}

// parseDatabases reads the "available databases [N]:" block and returns the
// "[*] name" entries that follow it (until a non-entry line).
func parseDatabases(lines []string) []string {
	var dbs []string
	inBlock := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		low := strings.ToLower(line)
		if strings.Contains(low, "available databases") && strings.Contains(line, "[") {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(line, "[*]") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "[*]"))
			// sqlmap's own "[*] starting/ending @ ..." log lines also begin with
			// "[*]"; exclude them so they don't pollute the database list.
			if name != "" && !strings.HasPrefix(strings.ToLower(name), "starting @") &&
				!strings.HasPrefix(strings.ToLower(name), "ending @") {
				dbs = append(dbs, name)
				continue
			}
		}
		// Any other line (a blank line, a log line, or an unrelated "[*]" marker)
		// ends the block — the entries are contiguous in sqlmap's output.
		break
	}
	return dbs
}

// parseDumpRows extracts the content of a sqlmap dump table block. sqlmap renders
// dumps as ASCII tables bordered by "+----+" rules; this returns the data rows
// (everything between the first and last border line) joined by newlines.
func parseDumpRows(lines []string) string {
	start, end := -1, -1
	for i, raw := range lines {
		if isTableBorder(strings.TrimSpace(raw)) {
			if start < 0 {
				start = i
			}
			end = i
		}
	}
	if start < 0 || end <= start {
		return ""
	}
	var rows []string
	for _, raw := range lines[start+1 : end] {
		line := strings.TrimSpace(raw)
		if line == "" || isTableBorder(line) {
			continue
		}
		rows = append(rows, line)
	}
	return strings.Join(rows, "\n")
}

// isTableBorder reports whether a line is a sqlmap dump border rule, e.g.
// "+------+--------+" (only '+' and '-' after trimming, with at least one '+').
func isTableBorder(line string) bool {
	if line == "" || !strings.HasPrefix(line, "+") {
		return false
	}
	for _, r := range line {
		if r != '+' && r != '-' {
			return false
		}
	}
	return true
}

// stripPrefix removes a leading sqlmap log marker like "[INFO] " / "[12:00:00] "
// for cleaner evidence; it only trims a single leading "[...]" token.
func stripPrefix(line string) string {
	if strings.HasPrefix(line, "[") {
		if idx := strings.IndexByte(line, ']'); idx > 0 && idx+1 < len(line) {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return line
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

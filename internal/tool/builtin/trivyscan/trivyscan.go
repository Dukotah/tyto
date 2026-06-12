// Package trivyscan is a runtime-detected shell-out adapter that drives Aqua
// Security's Trivy scanner for dependency / container-image / filesystem CVE
// analysis against an authorized target. tyto ships its own lightweight CVE
// matchers (see the cvematch tool) so it stays a single offline binary by
// default; this adapter is the OPT-IN bridge to Trivy's full vulnerability
// database (OS packages + language lockfiles + image layers) when an operator
// has the trivy binary installed.
//
// If trivy is not available in the execution backend it DEGRADES GRACEFULLY: a
// single info finding and Success=true, never an error. The live shell-out path
// is only taken when the operator has trivy present, so it is exercised in the
// field, not in CI.
//
// It is CategoryScan / RiskLow: Trivy reads packages/lockfiles/image metadata
// and matches them against a local vuln DB — it sends no probes at a live
// target — so the Scope Guard gates it against the engagement ceiling as a
// benign scanning step before Execute is reached.
package trivyscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// Tool implements an external Trivy CVE-scanning adapter.
type Tool struct{}

// New returns a trivyscan Tool.
func New() *Tool { return &Tool{} }

// Name implements tool.Tool.
func (t *Tool) Name() string { return "trivyscan" }

// Category implements tool.Tool.
func (t *Tool) Category() action.Category { return action.CategoryScan }

// MaxRisk implements tool.Tool. Trivy matches package metadata against a vuln
// DB without contacting the target, so RiskLow.
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// maxOutput caps captured combined output (~8 MiB). A Trivy image/fs scan can
// emit a large JSON document; this bounds memory while leaving ample room for a
// few thousand vulnerabilities before the cap clips the tail.
const maxOutput = 8 << 20

// maxFindings caps how many parsed findings we retain from one scan, so a
// dependency-bloated target can't flood state with thousands of CVEs.
const maxFindings = 300

// descMax truncates a finding description to keep reports/state compact.
const descMax = 240

// Execute detects the trivy binary and, when present, runs a JSON scan in the
// mode inferred from the target/params and parses each vulnerability into a
// state.Finding. With trivy absent it degrades to a single info finding and
// Success=true.
func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}

	bin := adapter.Detect("trivy")
	if bin == "" {
		res.Findings = append(res.Findings, adapter.Missing("trivy", a.Target, "apt install trivy"))
		res.Success = true
		res.Output = "trivy not installed; skipped (graceful degrade)"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	target := strings.TrimSpace(a.Target)
	if target == "" {
		res.Success = true
		res.Output = "trivy: no target provided; nothing to scan"
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	// Honor cancellation before launching the external process.
	select {
	case <-ctx.Done():
		res.FinishedAt = time.Now().UTC()
		res.Err = ctx.Err().Error()
		return res, ctx.Err()
	default:
	}

	subcommand := trivyMode(a.Params["mode"], target)

	// --format json: one document we parse; --quiet: suppress progress/banner
	// noise so stdout stays clean JSON. --scanners vuln keeps it to CVEs (not
	// secret/misconfig scanning, which produces a different schema).
	args := []string{subcommand, "--format", "json", "--quiet", "--scanners", "vuln"}
	if v := strings.TrimSpace(a.Params["severity"]); v != "" {
		args = append(args, "--severity", strings.ToUpper(v))
	}
	args = append(args, target)

	// trivy may exit non-zero (e.g. --exit-code on found vulns, or a partial
	// scan) yet still print a useful JSON document; parse regardless.
	out, runErr := adapter.Run(ctx, bin, args, maxOutput)

	findings := parseTrivyJSON(out)
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%s-%d", a.ID, i)
		findings[i].Tool = t.Name()
		if findings[i].FoundAt.IsZero() {
			findings[i].FoundAt = time.Now().UTC()
		}
	}
	res.Findings = append(res.Findings, findings...)

	summary := fmt.Sprintf("trivy %s %s: %d vuln finding(s)", subcommand, target, len(findings))
	if runErr != nil {
		summary += fmt.Sprintf(" — tool exit: %v", runErr)
	}
	res.Success = true
	res.Output = summary
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

// trivyMode picks the Trivy subcommand. An explicit params["mode"] (fs / image
// / repo / rootfs) wins; otherwise it is inferred from the target shape: a
// VCS-looking URL → repo, a filesystem-looking path (absolute, ./, or
// drive-letter) → fs, and anything else (a registry image reference like
// "nginx:1.21" or "alpine") → image, which is Trivy's default subject.
func trivyMode(mode, target string) string {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case "fs", "filesystem":
		return "fs"
	case "image", "container":
		return "image"
	case "repo", "repository":
		return "repo"
	case "rootfs":
		return "rootfs"
	}

	t := strings.TrimSpace(target)
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(lower, "git@"), strings.HasPrefix(lower, "git://"),
		strings.HasSuffix(lower, ".git"):
		return "repo"
	case strings.HasPrefix(t, "/"), strings.HasPrefix(t, "./"), strings.HasPrefix(t, "../"),
		strings.HasPrefix(t, "."), looksLikeWindowsPath(t):
		return "fs"
	default:
		return "image"
	}
}

// looksLikeWindowsPath reports whether t begins with a drive-letter path like
// "C:\..." or "C:/..." so a Windows filesystem target routes to `trivy fs`.
func looksLikeWindowsPath(t string) bool {
	if len(t) < 3 {
		return false
	}
	c := t[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return false
	}
	return t[1] == ':' && (t[2] == '\\' || t[2] == '/')
}

// trivyReport mirrors the subset of Trivy's --format json document we consume.
// Trivy nests vulnerabilities under Results[] (one per scanned artifact target,
// e.g. an OS package set or a lockfile), each holding a Vulnerabilities[] list.
type trivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Class           string      `json:"Class"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	PrimaryURL       string               `json:"PrimaryURL"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
}

// trivyCVSS is one scoring source's entry (nvd, redhat, ...) in the CVSS map.
type trivyCVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
	V2Vector string  `json:"V2Vector"`
}

// parseTrivyJSON parses a Trivy --format json document into findings, one per
// vulnerability. It is deliberately tolerant — a non-JSON / empty document
// yields no findings rather than an error — and pure (no IDs/timestamps
// stamped) so it is unit-testable on a captured sample without the trivy binary
// present. Findings are deduped by (VulnerabilityID, PkgName) and capped at
// maxFindings.
func parseTrivyJSON(out string) []state.Finding {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var rep trivyReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		return nil
	}

	var findings []state.Finding
	seen := make(map[string]bool)
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true

			// Title: prefer Trivy's human title, fall back to the CVE id, and
			// always anchor the affected package so the report is actionable.
			head := strings.TrimSpace(v.Title)
			if head == "" {
				head = v.VulnerabilityID
			}
			title := head
			if v.PkgName != "" {
				title = fmt.Sprintf("%s (%s)", head, v.PkgName)
			}

			findings = append(findings, state.Finding{
				Title:       title,
				Severity:    parseSeverity(v.Severity),
				Target:      trivyTarget(r),
				Description: buildDescription(v),
				Evidence:    buildEvidence(r, v),
				CVSS:        pickCVSSVector(v.CVSS),
				Validated:   true, // Trivy matched an installed version against a known CVE
			})
			if len(findings) >= maxFindings {
				return findings
			}
		}
	}
	return findings
}

// trivyTarget chooses the most specific locator for a result's findings: the
// per-result Target (e.g. "package-lock.json" or an OS like "alpine:3.18"),
// falling back to the result Type when Target is empty.
func trivyTarget(r trivyResult) string {
	if t := strings.TrimSpace(r.Target); t != "" {
		return t
	}
	return strings.TrimSpace(r.Type)
}

// buildDescription folds the CVE id, package, installed and fixed versions into
// a compact, operator-actionable line, then appends Trivy's prose (truncated).
func buildDescription(v trivyVuln) string {
	var sb strings.Builder
	sb.WriteString(v.VulnerabilityID)
	if v.PkgName != "" {
		sb.WriteString(" in ")
		sb.WriteString(v.PkgName)
		if v.InstalledVersion != "" {
			sb.WriteString(" ")
			sb.WriteString(v.InstalledVersion)
		}
	}
	if v.FixedVersion != "" {
		sb.WriteString("; fixed in ")
		sb.WriteString(v.FixedVersion)
	} else {
		sb.WriteString("; no fixed version available")
	}
	if d := strings.TrimSpace(v.Description); d != "" {
		sb.WriteString(" — ")
		sb.WriteString(d)
	}
	out := sb.String()
	if len(out) > descMax {
		out = out[:descMax]
	}
	return out
}

// buildEvidence records the raw, reproducible facts: where it was found and the
// exact version pair + reference URL, so an operator can confirm independently.
func buildEvidence(r trivyResult, v trivyVuln) string {
	var parts []string
	if loc := trivyTarget(r); loc != "" {
		parts = append(parts, "location="+loc)
	}
	parts = append(parts, "cve="+v.VulnerabilityID)
	if v.PkgName != "" {
		parts = append(parts, "pkg="+v.PkgName)
	}
	if v.InstalledVersion != "" {
		parts = append(parts, "installed="+v.InstalledVersion)
	}
	if v.FixedVersion != "" {
		parts = append(parts, "fixed="+v.FixedVersion)
	}
	if v.PrimaryURL != "" {
		parts = append(parts, "ref="+v.PrimaryURL)
	}
	return strings.Join(parts, " ")
}

// pickCVSSVector returns a CVSS v3.1 vector string from Trivy's per-source CVSS
// map, preferring NVD's scoring, then any source that carries a v3 vector. Trivy
// keys the map by scoring vendor (nvd, redhat, ghsa, ...). Returns "" when no
// v3 vector is present.
func pickCVSSVector(m map[string]trivyCVSS) string {
	if m == nil {
		return ""
	}
	if c, ok := m["nvd"]; ok && c.V3Vector != "" {
		return c.V3Vector
	}
	for _, c := range m {
		if c.V3Vector != "" {
			return c.V3Vector
		}
	}
	return ""
}

// parseSeverity maps Trivy's UPPERCASE severity string to a state.Severity, with
// anything unrecognized (incl. "UNKNOWN") falling back to info.
func parseSeverity(s string) state.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return state.SeverityCritical
	case "HIGH":
		return state.SeverityHigh
	case "MEDIUM":
		return state.SeverityMedium
	case "LOW":
		return state.SeverityLow
	default:
		return state.SeverityInfo
	}
}

package bounty

import (
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/state"
)

// --- Classification --------------------------------------------------------

func TestClassify_PayableClasses(t *testing.T) {
	cases := []struct {
		name string
		f    state.Finding
		want PayClass
	}{
		{"takeover by tool", state.Finding{Tool: "subtakeover", Title: "Possible subdomain takeover (Heroku) on app.example.com"}, ClassSubdomainTakeover},
		{"takeover by title", state.Finding{Tool: "nucleiscan", Title: "Dangling CNAME points to unclaimed S3 bucket"}, ClassSubdomainTakeover},
		{"git by tool", state.Finding{Tool: "dotgit", Title: "Exposed .git directory (source code disclosure)"}, ClassExposedGit},
		{"secret by tool", state.Finding{Tool: "jsmine", Title: "Exposed secret in JavaScript: AWS access key"}, ClassExposedSecret},
		{"secret by title", state.Finding{Tool: "secretscan", Title: "Leaked AWS secret access key in response"}, ClassExposedSecret},
		{"config by title", state.Finding{Tool: "dirfuzz", Title: "Exposed .env file at /.env"}, ClassExposedConfig},
		{"cve by tool", state.Finding{Tool: "cvematch", Title: "CVE-2021-44228 affects log4j 2.14.1"}, ClassKnownCVE},
		{"injection", state.Finding{Tool: "webinject", Title: "Reflected cross-site scripting (XSS) in q parameter"}, ClassInjection},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.f); got != c.want {
				t.Fatalf("Classify(%q) = %v, want %v", c.f.Title, got, c.want)
			}
		})
	}
}

func TestClassify_NeverSubmitClasses(t *testing.T) {
	cases := []struct {
		name string
		f    state.Finding
		want PayClass
	}{
		{"missing header", state.Finding{Tool: "webcheck", Title: "HTTP missing security headers", Severity: state.SeverityInfo}, ClassMissingHeader},
		{"missing csp", state.Finding{Tool: "webcheck", Title: "Missing Content-Security-Policy header"}, ClassMissingHeader},
		{"version banner", state.Finding{Tool: "whatweb", Title: "Server version disclosed: nginx 1.18.0", Severity: state.SeverityInfo}, ClassVersionDisclosure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.f)
			if got != c.want {
				t.Fatalf("Classify(%q) = %v, want %v", c.f.Title, got, c.want)
			}
			if !got.neverSubmit() {
				t.Fatalf("class %v should be never-submit", got)
			}
		})
	}
}

// --- Tiering: the gate fix -------------------------------------------------

// A takeover finding with NO active verifier must land in CANDIDATE actionable,
// not noise. This is the core regression the package fixes.
func TestBuild_TakeoverIsCandidateNotNoise(t *testing.T) {
	findings := []state.Finding{
		{ID: "STO-1", Tool: "subtakeover", Title: "Possible subdomain takeover (GitHub Pages) on docs.example.com",
			Target: "https://docs.example.com", Severity: state.SeverityHigh,
			Evidence: "CNAME -> example.github.io; 404 'There isn't a GitHub Pages site here'", Validated: false},
	}
	g := Build(findings, nil)

	if len(g.Noise) != 0 {
		t.Fatalf("takeover must not be noise; got %d noise issues", len(g.Noise))
	}
	if len(g.Candidate) != 1 {
		t.Fatalf("want 1 candidate, got %d (validated=%d)", len(g.Candidate), len(g.Validated))
	}
	iss := g.Candidate[0]
	if iss.Tier != TierCandidate {
		t.Fatalf("tier = %v, want candidate", iss.Tier)
	}
	if iss.Class != ClassSubdomainTakeover {
		t.Fatalf("class = %v, want takeover", iss.Class)
	}
	if !iss.Actionable() {
		t.Fatal("takeover candidate must be actionable")
	}
	// And it must appear in the actionable body.
	found := false
	for _, a := range g.Actionable() {
		if a.Class == ClassSubdomainTakeover {
			found = true
		}
	}
	if !found {
		t.Fatal("takeover missing from Actionable() body")
	}
}

// A missing-security-header finding must land in NOISE and never be submittable,
// even if marked validated or given a high severity.
func TestBuild_MissingHeaderIsNoiseNeverSubmittable(t *testing.T) {
	findings := []state.Finding{
		{ID: "H-1", Tool: "webcheck", Title: "HTTP missing security headers",
			Target: "https://www.example.com", Severity: state.SeverityHigh, Validated: true},
	}
	g := Build(findings, map[string]bool{"H-1": true}) // even "confirmed"

	if len(g.Validated) != 0 || len(g.Candidate) != 0 {
		t.Fatalf("missing-header must never be actionable; validated=%d candidate=%d", len(g.Validated), len(g.Candidate))
	}
	if len(g.Noise) != 1 {
		t.Fatalf("want 1 noise issue, got %d", len(g.Noise))
	}
	if g.Noise[0].Tier != TierNoise {
		t.Fatalf("tier = %v, want noise", g.Noise[0].Tier)
	}
	if g.Noise[0].Actionable() {
		t.Fatal("noise must not be actionable")
	}
}

// A confirmed payable finding lands in VALIDATED, not just CANDIDATE.
func TestBuild_ConfirmedIsValidated(t *testing.T) {
	findings := []state.Finding{
		{ID: "X-1", Tool: "webinject", Title: "Reflected XSS in q parameter",
			Target: "https://a.example.com/?q=", Severity: state.SeverityHigh, Validated: true},
	}
	g := Build(findings, nil)
	if len(g.Validated) != 1 {
		t.Fatalf("want 1 validated, got %d", len(g.Validated))
	}
	if g.Validated[0].Tier != TierValidated {
		t.Fatalf("tier = %v, want validated", g.Validated[0].Tier)
	}
}

// confirmedIDs (the external verifier signal) promotes a finding to VALIDATED
// even when its own Validated flag is false.
func TestBuild_ConfirmedIDsPromotes(t *testing.T) {
	findings := []state.Finding{
		{ID: "S-1", Tool: "secretscan", Title: "Exposed secret: GitHub token",
			Target: "https://b.example.com", Severity: state.SeverityHigh, Validated: false},
	}
	g := Build(findings, map[string]bool{"S-1": true})
	if len(g.Validated) != 1 || len(g.Candidate) != 0 {
		t.Fatalf("confirmedIDs should promote to validated; validated=%d candidate=%d", len(g.Validated), len(g.Candidate))
	}
}

// --- Dedup across hosts -----------------------------------------------------

// The same systemic issue seen on 5 hosts collapses into ONE issue listing all 5
// targets — not 5 submissions.
func TestBuild_DedupCollapsesAcrossHosts(t *testing.T) {
	hosts := []string{
		"https://a.example.com", "https://b.example.com", "https://c.example.com",
		"https://d.example.com", "https://e.example.com",
	}
	var findings []state.Finding
	for i, h := range hosts {
		findings = append(findings, state.Finding{
			ID:       "G-" + string(rune('1'+i)),
			Tool:     "dotgit",
			Title:    "Exposed .git directory (source code disclosure)",
			Target:   h,
			Severity: state.SeverityHigh,
			Evidence: "200 OK on /.git/HEAD",
		})
	}
	g := Build(findings, nil)

	total := len(g.Validated) + len(g.Candidate) + len(g.Noise)
	if total != 1 {
		t.Fatalf("want exactly 1 collapsed issue, got %d (v=%d c=%d n=%d)",
			total, len(g.Validated), len(g.Candidate), len(g.Noise))
	}
	if len(g.Candidate) != 1 {
		t.Fatalf("want collapsed issue in candidate, got candidate=%d", len(g.Candidate))
	}
	iss := g.Candidate[0]
	if iss.Count() != 5 {
		t.Fatalf("want 5 affected targets, got %d: %v", iss.Count(), iss.Targets)
	}
	// targets sorted & deduped
	for i := 1; i < len(iss.Targets); i++ {
		if iss.Targets[i-1] >= iss.Targets[i] {
			t.Fatalf("targets not sorted/unique: %v", iss.Targets)
		}
	}
	if len(iss.Evidence) != 5 {
		t.Fatalf("want 5 per-target evidence rows, got %d", len(iss.Evidence))
	}
}

// Re-running the same check on one host must not double-count the target.
func TestBuild_DedupSameTargetRepeated(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "dotgit", Title: "Exposed .git directory", Target: "https://a.example.com", Severity: state.SeverityHigh, Evidence: "run1"},
		{ID: "2", Tool: "dotgit", Title: "Exposed .git directory", Target: "https://a.example.com", Severity: state.SeverityHigh, Evidence: "run2"},
	}
	g := Build(findings, nil)
	if len(g.Candidate) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(g.Candidate))
	}
	if c := g.Candidate[0].Count(); c != 1 {
		t.Fatalf("same target should not double-count; got %d targets", c)
	}
	if len(g.Candidate[0].Evidence) != 2 {
		t.Fatalf("both evidence rows should be retained; got %d", len(g.Candidate[0].Evidence))
	}
}

// --- Ranking ---------------------------------------------------------------

// Takeover/secret/.git outrank CVE, which outrank injection, in the actionable
// body.
func TestBuild_RankingPayabilityOrder(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "webinject", Title: "Reflected XSS in q", Target: "https://x.example.com", Severity: state.SeverityHigh},
		{ID: "2", Tool: "cvematch", Title: "CVE-2021-1 affects nginx 1.0", Target: "https://x.example.com", Severity: state.SeverityHigh},
		{ID: "3", Tool: "subtakeover", Title: "Subdomain takeover on x.example.com", Target: "https://x.example.com", Severity: state.SeverityHigh},
	}
	g := Build(findings, nil)
	body := g.Actionable()
	if len(body) != 3 {
		t.Fatalf("want 3 actionable, got %d", len(body))
	}
	if body[0].Class != ClassSubdomainTakeover {
		t.Fatalf("first should be takeover, got %v", body[0].Class)
	}
	if body[1].Class != ClassKnownCVE {
		t.Fatalf("second should be CVE, got %v", body[1].Class)
	}
	if body[2].Class != ClassInjection {
		t.Fatalf("third should be injection, got %v", body[2].Class)
	}
}

// Validated issues precede candidates in the actionable body.
func TestGate_ValidatedBeforeCandidate(t *testing.T) {
	findings := []state.Finding{
		{ID: "c", Tool: "subtakeover", Title: "Subdomain takeover on a", Target: "https://a.example.com", Severity: state.SeverityHigh},
		{ID: "v", Tool: "webinject", Title: "Reflected XSS in q", Target: "https://b.example.com", Severity: state.SeverityMedium, Validated: true},
	}
	g := Build(findings, nil)
	body := g.Actionable()
	if len(body) != 2 {
		t.Fatalf("want 2, got %d", len(body))
	}
	if body[0].Tier != TierValidated {
		t.Fatalf("validated must come first; got %v", body[0].Tier)
	}
	if body[1].Tier != TierCandidate {
		t.Fatalf("candidate must follow; got %v", body[1].Tier)
	}
}

// --- Writeup ---------------------------------------------------------------

// A writeup contains title, repro, impact and evidence — paste-ready.
func TestRenderIssue_ContainsRequiredSections(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "dotgit", Title: "Exposed .git directory (source code disclosure)",
			Target: "https://a.example.com", Severity: state.SeverityHigh,
			Description: "The /.git/ directory is publicly readable.",
			Evidence:    "GET /.git/HEAD -> 200 'ref: refs/heads/main'",
			CVSS:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
	}
	g := Build(findings, nil)
	if len(g.Candidate) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(g.Candidate))
	}
	w := g.Candidate[0].Writeup
	for _, want := range []string{
		"Exposed .git directory",
		"**Severity:**",
		"**Reproduction:**",
		"**Impact:**",
		"**Evidence:**",
		"a.example.com",
	} {
		if !strings.Contains(w, want) {
			t.Fatalf("writeup missing %q\n---\n%s", want, w)
		}
	}
	// CVSS derived and rendered.
	if !strings.Contains(w, "CVSS") {
		t.Fatalf("writeup missing CVSS\n%s", w)
	}
	if g.Candidate[0].CVSSScore <= 0 {
		t.Fatalf("CVSS score not derived: %v", g.Candidate[0].CVSSScore)
	}
}

// A writeup still has repro+impact even when the tool emitted none (defaults).
func TestRenderIssue_DefaultsFillReproImpact(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "subtakeover", Title: "Subdomain takeover on app.example.com",
			Target: "https://app.example.com", Severity: state.SeverityHigh},
	}
	g := Build(findings, nil)
	w := g.Candidate[0].Writeup
	if !strings.Contains(w, "**Reproduction:**") || !strings.Contains(w, "claim") {
		t.Fatalf("expected default repro for takeover\n%s", w)
	}
	if !strings.Contains(w, "**Impact:**") || !strings.Contains(w, "trusted hostname") {
		t.Fatalf("expected default impact for takeover\n%s", w)
	}
}

// --- Gate render -----------------------------------------------------------

func TestRenderGate_SeparatesNoiseFromActionable(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "subtakeover", Title: "Subdomain takeover on a", Target: "https://a.example.com", Severity: state.SeverityHigh, Evidence: "dangling"},
		{ID: "2", Tool: "webcheck", Title: "HTTP missing security headers", Target: "https://a.example.com", Severity: state.SeverityInfo},
	}
	g := Build(findings, nil)
	out := RenderGate("test-eng", g)

	if !strings.Contains(out, "## Actionable (submit these)") {
		t.Fatalf("missing actionable section\n%s", out)
	}
	if !strings.Contains(out, "## Retained as noise (never submitted)") {
		t.Fatalf("missing noise section\n%s", out)
	}
	// The takeover must appear above the noise section.
	ai := strings.Index(out, "Subdomain takeover")
	ni := strings.Index(out, "## Retained as noise")
	if ai < 0 || ni < 0 || ai > ni {
		t.Fatalf("takeover should appear in actionable body, before noise section\n%s", out)
	}
	// The missing-header title must NOT appear in the actionable body — only in
	// the noise list (after the noise heading).
	mh := strings.Index(out, "missing security headers")
	if mh >= 0 && mh < ni {
		t.Fatalf("missing-header leaked into actionable body\n%s", out)
	}
}

// Build never drops a finding: every input lands in exactly one bucket.
func TestBuild_NothingDropped(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "subtakeover", Title: "Subdomain takeover on a", Target: "https://a.example.com", Severity: state.SeverityHigh},
		{ID: "2", Tool: "webcheck", Title: "HTTP missing security headers", Target: "https://a.example.com", Severity: state.SeverityInfo},
		{ID: "3", Tool: "whatweb", Title: "Server version disclosed: nginx 1.18", Target: "https://a.example.com", Severity: state.SeverityInfo},
		{ID: "4", Tool: "portscan", Title: "Open port 8080", Target: "https://a.example.com", Severity: state.SeverityInfo},
	}
	g := Build(findings, nil)
	total := len(g.Validated) + len(g.Candidate) + len(g.Noise)
	if total != 4 {
		t.Fatalf("want 4 distinct issues accounted for, got %d", total)
	}
}

// TestClassify_NegativeTitlesNeverPayable proves the negation guard: defensive /
// "checked and it's fine" titles must NOT reach a payable (submittable) class —
// the exact false-positive vector the verifier reproduced.
func TestClassify_NegativeTitlesNeverPayable(t *testing.T) {
	negatives := []struct {
		tool, title string
	}{
		{"webinject", "No XSS vulnerabilities found"},
		{"webcheck", "XSS protection (CSP) is enabled"},
		{"sqliexploit", "Tested for SQLi - not vulnerable"},
		{"webinject", "SSRF filter correctly blocks internal IPs"},
		{"nuclei", "This misconfiguration affects all users"},
		{"dotgit", "Reviewed git directory layout, nothing exposed"},
		{"subtakeover", "unclaimed namespace reserved by org"},
	}
	for _, n := range negatives {
		f := state.Finding{ID: "x", Tool: n.tool, Title: n.title, Target: "https://a.example.com", Severity: state.SeverityMedium}
		c := Classify(f)
		if c.payable() {
			t.Errorf("title %q classified payable (%s) — must be non-submittable", n.title, c.label())
		}
		g := Build([]state.Finding{f}, nil)
		if len(g.Actionable()) != 0 {
			t.Errorf("title %q reached the actionable/submit body — must stay noise", n.title)
		}
	}
}

// TestBuild_InfoNegativeNeverActionable reproduces the live-run bug: the tools'
// INFO-severity negative results ("No subdomain-takeover detected", "No exposed
// .git directory") carry a payable-class title AND Validated=true, but must NEVER
// reach the actionable submit body — they describe the absence of a bug.
func TestBuild_InfoNegativeNeverActionable(t *testing.T) {
	findings := []state.Finding{
		{ID: "1", Tool: "subtakeover", Title: "No subdomain-takeover detected", Target: "https://www.x.com", Severity: state.SeverityInfo, Validated: true},
		{ID: "2", Tool: "dotgit", Title: "No exposed .git directory", Target: "https://www.x.com", Severity: state.SeverityInfo, Validated: true},
	}
	g := Build(findings, nil)
	if len(g.Actionable()) != 0 {
		t.Fatalf("INFO-severity negatives leaked into actionable: %d issue(s)", len(g.Actionable()))
	}
	// A genuine HIGH takeover with the same tool must still be actionable.
	real := []state.Finding{{ID: "3", Tool: "subtakeover", Title: "Possible subdomain takeover (GitHub Pages)", Target: "https://stale.x.com", Severity: state.SeverityHigh, Validated: true}}
	if len(Build(real, nil).Actionable()) != 1 {
		t.Fatal("a genuine HIGH takeover must remain actionable")
	}
}

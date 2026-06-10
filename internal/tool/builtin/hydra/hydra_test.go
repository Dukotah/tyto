package hydra

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool/adapter"
)

// sampleHit is captured hydra output with one valid SSH pair found.
const sampleHit = `Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] attacking ssh://10.0.0.5:22/
[22][ssh] host: 10.0.0.5   login: admin   password: admin123
1 of 1 target successfully completed, 1 valid password found
`

// sampleMiss is hydra output where no valid pair was found.
const sampleMiss = `Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] attacking ssh://10.0.0.5:22/
1 of 1 target completed, 0 valid passwords found
`

func TestParseHydraHit(t *testing.T) {
	findings, creds := parseHydra(sampleHit)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != state.SeverityCritical {
		t.Errorf("want SeverityCritical, got %v", f.Severity)
	}
	if !f.Validated {
		t.Errorf("recovered-credential finding should be Validated")
	}
	if !strings.Contains(f.Title, "admin:admin123") || !strings.Contains(f.Title, "ssh") {
		t.Errorf("finding title missing login:password/service: %q", f.Title)
	}
	if f.Target != "10.0.0.5" {
		t.Errorf("finding target = %q, want 10.0.0.5", f.Target)
	}

	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d: %+v", len(creds), creds)
	}
	c := creds[0]
	if c.Kind != state.CredPassword {
		t.Errorf("cred kind = %q, want password", c.Kind)
	}
	if c.Username != "admin" || c.Secret != "admin123" {
		t.Errorf("cred = %q/%q, want admin/admin123", c.Username, c.Secret)
	}
	if c.Source != "hydra" || c.Target != "10.0.0.5" {
		t.Errorf("cred source/target = %q/%q, want hydra/10.0.0.5", c.Source, c.Target)
	}
}

func TestParseHydraMiss(t *testing.T) {
	findings, creds := parseHydra(sampleMiss)
	if len(findings) != 0 {
		t.Errorf("expected no parsed findings on a miss, got %d: %+v", len(findings), findings)
	}
	if len(creds) != 0 {
		t.Errorf("expected no credentials on a miss, got %d", len(creds))
	}
}

// TestExecuteMissService asserts the info finding when no service param is given.
func TestExecuteMissService(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a1",
		Target: "10.0.0.5",
		Params: map[string]string{"user": "admin", "pass": "x"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected 1 Info finding, got %+v", res.Findings)
	}
	if !strings.Contains(res.Findings[0].Title, "service") {
		t.Errorf("title = %q, want it to mention 'service'", res.Findings[0].Title)
	}
}

// TestExecuteMissCreds asserts the info finding when a cred source is missing.
func TestExecuteMissCreds(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a2",
		Target: "10.0.0.5",
		Params: map[string]string{"service": "ssh", "user": "admin"}, // no pass source
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected 1 Info finding, got %+v", res.Findings)
	}
	if !strings.Contains(strings.ToLower(res.Findings[0].Title), "user(list) + pass(list)") {
		t.Errorf("title = %q, want it to mention the missing cred sources", res.Findings[0].Title)
	}
}

// TestExecuteGracefulDegrade asserts that with all params present but hydra not
// installed, Execute still succeeds with the standard "hydra not available"
// Info finding. Skipped if hydra happens to be on PATH (live attack would run).
func TestExecuteGracefulDegrade(t *testing.T) {
	if adapter.Detect("hydra") != "" {
		t.Skip("hydra is installed on this host; graceful-degrade path not exercised")
	}
	res, err := New().Execute(context.Background(), action.Action{
		ID:     "a3",
		Target: "10.0.0.5",
		Params: map[string]string{"service": "ssh", "userlist": "users.txt", "passlist": "pass.txt"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected Success=true on graceful degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("graceful-degrade finding should be SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Title), "hydra not available") {
		t.Errorf("title = %q, want it to mention 'hydra not available'", f.Title)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"ssh://h:22/x": "h",
		"10.0.0.5":     "10.0.0.5",
		"10.0.0.5:22":  "10.0.0.5",
		"example.com":  "example.com",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// Compile-time assertion that *Tool satisfies the tool.Tool contract.
var (
	_ interface {
		Name() string
		Category() action.Category
		MaxRisk() action.RiskLevel
		Execute(context.Context, action.Action) (action.Result, error)
	} = (*Tool)(nil)
)

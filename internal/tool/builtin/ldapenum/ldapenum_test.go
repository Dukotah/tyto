package ldapenum

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// TestExecute_GracefulDegrade exercises the path on a box WITHOUT any LDAP
// enumeration tool installed (CI/dev): Execute must succeed and emit the single
// "No LDAP enumeration tool installed" info finding rather than erroring.
func TestExecute_GracefulDegrade(t *testing.T) {
	if detectTool() != "" {
		t.Skip("an LDAP enumeration tool is installed; graceful-degrade path not applicable")
	}
	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Tool: "ldapenum", Target: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Execute returned error on degrade path: %v", err)
	}
	if !res.Success {
		t.Fatal("expected Success=true on graceful degrade")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected exactly 1 info finding, got %d", len(res.Findings))
	}
	if !strings.Contains(res.Findings[0].Title, "No LDAP enumeration tool") {
		t.Errorf("unexpected degrade finding: %q", res.Findings[0].Title)
	}
}

func TestToolMeta(t *testing.T) {
	tl := New()
	if tl.Name() != "ldapenum" {
		t.Errorf("Name = %q", tl.Name())
	}
	if tl.Category() != action.CategoryIdentity {
		t.Errorf("Category = %v, want identity", tl.Category())
	}
	if tl.MaxRisk() != action.RiskMedium {
		t.Errorf("MaxRisk = %v, want medium", tl.MaxRisk())
	}
}

// sampleLDAP is captured-style NetExec `ldap --users --groups --pass-pol` output.
const sampleLDAP = `
LDAP        10.0.0.5        389    DC01             [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local) (signing:True)
LDAP        10.0.0.5        389    DC01             [+] corp.local\svc-test:Summer2024
LDAP        10.0.0.5        389    DC01             -Username-                    -Last PW Set-
LDAP        10.0.0.5        389    DC01             Administrator                 2023-01-01
LDAP        10.0.0.5        389    DC01             Guest                         <never>
LDAP        10.0.0.5        389    DC01             svc-sql                       2022-05-05
LDAP        10.0.0.5        389    DC01             Minimum password length: 5
LDAP        10.0.0.5        389    DC01             Password Complexity Flags: 000000
`

func TestParseLDAP(t *testing.T) {
	findings, assets := parseLDAP(sampleLDAP)

	// Expect: users finding, weak-min-length (medium), complexity-disabled (medium).
	var users, weakLen, complexity bool
	for _, f := range findings {
		switch {
		case strings.Contains(f.Title, "users enumerated"):
			users = true
			if !strings.Contains(f.Evidence, "Administrator") || !strings.Contains(f.Evidence, "svc-sql") {
				t.Errorf("users finding missing enumerated names: %q", f.Evidence)
			}
		case strings.Contains(f.Title, "minimum length"):
			weakLen = true
			if f.Severity != state.SeverityMedium {
				t.Errorf("weak-length severity = %v, want medium", f.Severity)
			}
		case strings.Contains(f.Title, "complexity disabled"):
			complexity = true
			if f.Severity != state.SeverityMedium {
				t.Errorf("complexity severity = %v, want medium", f.Severity)
			}
		}
	}
	if !users || !weakLen || !complexity {
		t.Fatalf("missing findings: users=%v weakLen=%v complexity=%v (got %d findings)", users, weakLen, complexity, len(findings))
	}

	// The asset should carry the parsed domain + hostname.
	var found bool
	for _, a := range assets {
		if a.Attrs["service"] == "ldap" {
			found = true
			if a.Attrs["domain"] != "corp.local" {
				t.Errorf("asset domain = %q, want corp.local", a.Attrs["domain"])
			}
			if a.Attrs["hostname"] != "DC01" {
				t.Errorf("asset hostname = %q, want DC01", a.Attrs["hostname"])
			}
		}
	}
	if !found {
		t.Error("no ldap service asset emitted")
	}
}

func TestParseLDAP_Empty(t *testing.T) {
	findings, assets := parseLDAP("")
	if len(findings) != 0 {
		t.Errorf("expected no findings on empty output, got %d", len(findings))
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on empty output, got %d", len(assets))
	}
}

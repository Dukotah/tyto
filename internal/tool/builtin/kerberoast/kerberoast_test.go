package kerberoast

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

func TestExecute_GracefulDegrade(t *testing.T) {
	if detectTool() != "" {
		t.Skip("a roasting tool is installed; graceful-degrade path not applicable")
	}
	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Tool: "kerberoast", Target: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Execute errored on degrade path: %v", err)
	}
	if !res.Success || len(res.Findings) != 1 || res.Findings[0].Severity != state.SeverityInfo {
		t.Fatalf("expected one info degrade finding, got success=%v findings=%d", res.Success, len(res.Findings))
	}
	if len(res.Credentials) != 0 {
		t.Errorf("degrade path should recover no credentials, got %d", len(res.Credentials))
	}
}

func TestToolMeta(t *testing.T) {
	tl := New()
	if tl.Name() != "kerberoast" || tl.Category() != action.CategoryIdentity || tl.MaxRisk() != action.RiskMedium {
		t.Errorf("meta mismatch: name=%q cat=%v risk=%v", tl.Name(), tl.Category(), tl.MaxRisk())
	}
}

// sampleRoast mixes AS-REP and Kerberoast hashes as NetExec echoes them.
const sampleRoast = `
LDAP   10.0.0.5  389  DC01  [*] Total of records returned 1
LDAP   10.0.0.5  389  DC01  $krb5asrep$23$jdoe@CORP.LOCAL:a1b2c3d4e5f6$deadbeefcafe...
LDAP   10.0.0.5  389  DC01  [+] Writing AS_REP hashes to /tmp/x
LDAP   10.0.0.5  389  DC01  $krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/db01.corp.local~1433*$aaaa...
`

func TestParseRoast(t *testing.T) {
	creds, findings := parseRoast(sampleRoast, "10.0.0.5")
	if len(creds) != 2 {
		t.Fatalf("expected 2 recovered hashes, got %d", len(creds))
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	var sawASREP, sawTGS bool
	for _, c := range creds {
		if c.Kind != state.CredHash {
			t.Errorf("credential kind = %v, want hash", c.Kind)
		}
		switch {
		case strings.HasPrefix(c.Secret, "$krb5asrep$"):
			sawASREP = true
			if c.Username != "jdoe" {
				t.Errorf("AS-REP username = %q, want jdoe", c.Username)
			}
		case strings.HasPrefix(c.Secret, "$krb5tgs$"):
			sawTGS = true
			if c.Username != "svc-sql" {
				t.Errorf("TGS username = %q, want svc-sql", c.Username)
			}
		}
	}
	if !sawASREP || !sawTGS {
		t.Fatalf("missing a hash type: asrep=%v tgs=%v", sawASREP, sawTGS)
	}

	// AS-REP roastable should be High; kerberoastable SPN Medium.
	for _, f := range findings {
		if strings.Contains(f.Title, "AS-REP") && f.Severity != state.SeverityHigh {
			t.Errorf("AS-REP severity = %v, want high", f.Severity)
		}
		if strings.Contains(f.Title, "Kerberoastable") && f.Severity != state.SeverityMedium {
			t.Errorf("Kerberoast severity = %v, want medium", f.Severity)
		}
	}
}

func TestParseRoast_Dedup(t *testing.T) {
	dup := sampleRoast + sampleRoast
	creds, _ := parseRoast(dup, "10.0.0.5")
	if len(creds) != 2 {
		t.Errorf("expected dedup to 2 hashes, got %d", len(creds))
	}
}

func TestPrincipalOf(t *testing.T) {
	cases := map[string]string{
		"$krb5asrep$23$jdoe@CORP.LOCAL:abc$def": "jdoe",
		"$krb5tgs$23$*svc-sql$CORP.LOCAL$rest":  "svc-sql",
		"$krb5tgs$23$svc2$CORP.LOCAL$rest":      "svc2",
	}
	for in, want := range cases {
		if got := principalOf(in); got != want {
			t.Errorf("principalOf(%q) = %q, want %q", in, got, want)
		}
	}
}

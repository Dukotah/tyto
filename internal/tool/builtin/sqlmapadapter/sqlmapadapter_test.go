package sqlmapadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// injectableOutput is a trimmed but representative sqlmap run against a
// vulnerable endpoint: it confirms the injection, fingerprints the DBMS, and
// extracts the banner / current user / available databases.
const injectableOutput = `
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2}
[*] starting @ 12:00:00 /2026-06-09/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234
---
[12:00:03] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
banner: '5.7.41'
current user: 'root@localhost'
current database: 'acme'
[12:00:04] [INFO] fetching database names
available databases [2]:
[*] acme
[*] information_schema

[*] ending @ 12:00:05 /2026-06-09/
`

// cleanOutput is a sqlmap run where nothing is injectable.
const cleanOutput = `
[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [WARNING] GET parameter 'id' does not seem to be injectable
[12:00:03] [CRITICAL] all tested parameters do not appear to be injectable.
[*] ending @ 12:00:03 /2026-06-09/
`

func findByTitleContains(fs []state.Finding, sub string) *state.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, sub) {
			return &fs[i]
		}
	}
	return nil
}

func TestParseSqlmap_Injectable(t *testing.T) {
	fs := parseSqlmap(injectableOutput)

	// Confirmed injection finding with the exact CVSS vector.
	conf := findByTitleContains(fs, "SQL injection confirmed by sqlmap")
	if conf == nil {
		t.Fatalf("expected a confirmed-injection finding; got titles %v", titles(fs))
	}
	if conf.Severity != state.SeverityCritical {
		t.Errorf("confirmed finding severity = %v, want critical", conf.Severity)
	}
	if !conf.Validated {
		t.Errorf("confirmed finding should be Validated")
	}
	if conf.CVSS != sqlmapCVSS {
		t.Errorf("confirmed finding CVSS = %q, want %q", conf.CVSS, sqlmapCVSS)
	}
	if !strings.Contains(conf.Description, "MySQL") {
		t.Errorf("confirmed finding should mention DBMS MySQL; desc = %q", conf.Description)
	}

	// Banner extraction.
	if b := findByTitleContains(fs, "banner = 5.7.41"); b == nil {
		t.Errorf("expected banner extraction finding; got titles %v", titles(fs))
	} else if b.Severity != state.SeverityCritical {
		t.Errorf("banner finding severity = %v, want critical", b.Severity)
	}

	// Current user extraction.
	if u := findByTitleContains(fs, "current user = root@localhost"); u == nil {
		t.Errorf("expected current-user extraction finding; got titles %v", titles(fs))
	}

	// Databases extraction listing both names.
	d := findByTitleContains(fs, "database(s) enumerated")
	if d == nil {
		t.Fatalf("expected databases enumeration finding; got titles %v", titles(fs))
	}
	if !strings.Contains(d.Evidence, "acme") || !strings.Contains(d.Evidence, "information_schema") {
		t.Errorf("databases finding evidence should list both DBs; got %q", d.Evidence)
	}
	if !strings.Contains(d.Title, "2 database") {
		t.Errorf("databases finding title should report count 2; got %q", d.Title)
	}
}

func TestParseSqlmap_Clean(t *testing.T) {
	fs := parseSqlmap(cleanOutput)
	if len(fs) != 1 {
		t.Fatalf("clean run should yield exactly 1 finding; got %d: %v", len(fs), titles(fs))
	}
	if fs[0].Severity != state.SeverityInfo {
		t.Errorf("clean finding severity = %v, want info", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Title, "no injection confirmed") {
		t.Errorf("clean finding title = %q, want 'no injection confirmed'", fs[0].Title)
	}
}

func TestParseSqlmap_Dump(t *testing.T) {
	const dumpOut = `
[12:00:01] [INFO] GET parameter 'id' is vulnerable.
Database: acme
Table: users
[2 entries]
+----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | admin    | 5f4dcc3b5aa765d6 |
| 2  | alice    | e10adc3949ba59ab |
+----+----------+------------------+
`
	fs := parseSqlmap(dumpOut)
	d := findByTitleContains(fs, "dumped table rows")
	if d == nil {
		t.Fatalf("expected dumped-rows finding; got titles %v", titles(fs))
	}
	if !strings.Contains(d.Evidence, "admin") || !strings.Contains(d.Evidence, "alice") {
		t.Errorf("dump evidence should contain the row data; got %q", d.Evidence)
	}
}

// TestExecute_GracefulDegrade exercises the no-binary path. On this build host
// sqlmap is not installed, so Execute must return the Info "not available"
// finding and Success=true (graceful degrade).
func TestExecute_GracefulDegrade(t *testing.T) {
	tool := New()
	a := action.Action{ID: "a1", Target: "http://example.test/?id=1"}
	res, err := tool.Execute(context.Background(), a)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Errorf("Execute Success = false, want true on graceful degrade")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding on degrade; got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("degrade finding severity = %v, want info", f.Severity)
	}
	if !strings.Contains(f.Title, "sqlmap not available") {
		t.Errorf("degrade finding title = %q, want 'sqlmap not available'", f.Title)
	}
}

func TestMetadata(t *testing.T) {
	tool := New()
	if tool.Name() != "sqlmap" {
		t.Errorf("Name() = %q, want sqlmap", tool.Name())
	}
	if tool.Category() != action.CategoryExploit {
		t.Errorf("Category() = %v, want CategoryExploit", tool.Category())
	}
	if tool.MaxRisk() != action.RiskHigh {
		t.Errorf("MaxRisk() = %v, want RiskHigh", tool.MaxRisk())
	}
}

func TestBuildArgs_PostAndDump(t *testing.T) {
	a := action.Action{
		Target: "http://t/?id=1",
		Params: map[string]string{"data": "id=1", "dump": "true", "table": "users", "db": "acme"},
	}
	args := buildArgs(a)
	joined := strings.Join(args, " ")
	for _, want := range []string{"--batch", "--flush-session", "--dbs", "--data id=1", "--dump", "-T users", "-D acme"} {
		if !strings.Contains(joined, want) {
			t.Errorf("buildArgs missing %q; got %q", want, joined)
		}
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

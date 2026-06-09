package secretscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

const (
	awsKey    = "AKIAIOSFODNN7EXAMPLE"
	googleKey = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
)

// findingByTitle returns the first finding with the given title, or nil.
func findingByTitle(findings []state.Finding, title string) *state.Finding {
	for i := range findings {
		if findings[i].Title == title {
			return &findings[i]
		}
	}
	return nil
}

func TestExecute_FindsSecretsInPageAndScript(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
<script src="/app.js"></script>
</head><body>aws config: ` + awsKey + `</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var GOOGLE_KEY = "` + googleKey + `";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Output=%q Err=%q", res.Output, res.Err)
	}

	aws := findingByTitle(res.Findings, "Exposed AWS access key ID")
	if aws == nil {
		t.Fatalf("missing AWS finding; got %d findings: %+v", len(res.Findings), res.Findings)
	}
	if aws.Severity != state.SeverityHigh {
		t.Errorf("AWS finding severity = %v, want high", aws.Severity)
	}
	if !aws.Validated {
		t.Errorf("AWS finding should be Validated")
	}

	goog := findingByTitle(res.Findings, "Exposed Google API key")
	if goog == nil {
		t.Fatalf("missing Google API key finding (from /app.js); got: %+v", res.Findings)
	}
	if goog.Severity != state.SeverityHigh {
		t.Errorf("Google finding severity = %v, want high", goog.Severity)
	}

	// Redaction: the full secret must never appear in Evidence (nor Description).
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, awsKey) || strings.Contains(f.Evidence, googleKey) {
			t.Errorf("Evidence leaked full secret: %q", f.Evidence)
		}
		if strings.Contains(f.Description, awsKey) || strings.Contains(f.Description, googleKey) {
			t.Errorf("Description leaked full secret: %q", f.Description)
		}
	}
	// Sanity: the redacted evidence should still show the recognizable prefix.
	if !strings.Contains(aws.Evidence, "AKIA") {
		t.Errorf("AWS evidence should keep the leading prefix, got %q", aws.Evidence)
	}
	if !strings.Contains(aws.Evidence, "*") {
		t.Errorf("AWS evidence should be masked, got %q", aws.Evidence)
	}
}

func TestExecute_CleanServer_NoSecretFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><h1>Welcome</h1><p>Nothing to see here.</p></body></html>`))
	}))
	defer srv.Close()

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{ID: "a2", Target: srv.URL})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success, got Output=%q Err=%q", res.Output, res.Err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no secret findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestExecute_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing is listening

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{ID: "a3", Target: url})
	if err != nil {
		t.Fatalf("connection error should be returned as (res, nil), got err: %v", err)
	}
	if res.Success {
		t.Errorf("Success should be false on connection error")
	}
	if res.Err == "" || res.Output == "" {
		t.Errorf("expected Err and Output populated on connection error; Err=%q Output=%q", res.Err, res.Output)
	}
}

func TestSameHostScripts_BoundedAndSameHost(t *testing.T) {
	base := "http://example.com/index.html"
	body := []byte(`
<script src="/a.js"></script>
<script src="https://cdn.other.com/evil.js"></script>
<script src="b.js"></script>
<script src="//example.com/c.js"></script>
`)
	got := sameHostScripts(base, body)
	for _, u := range got {
		if strings.Contains(u, "other.com") {
			t.Errorf("cross-host script should be excluded: %q", u)
		}
	}
	if len(got) == 0 {
		t.Fatalf("expected same-host scripts, got none")
	}
}

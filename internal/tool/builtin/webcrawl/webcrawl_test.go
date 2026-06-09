package webcrawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

func crawlSite() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
			<a href="/search?q=hello">search</a>
			<a href="/about">about</a>
			<a href="https://external.example.com/x">offsite</a>
			<form action="/lookup" method="get"><input name="id"><input name="ref"></form>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>about us</html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>results</html>`))
	})
	mux.HandleFunc("/lookup", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>lookup</html>`))
	})
	return httptest.NewServer(mux)
}

func TestWebcrawlFindsParameterizedEndpoints(t *testing.T) {
	srv := crawlSite()
	defer srv.Close()

	res, err := New().Execute(context.Background(), action.Action{ID: "a1", Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("expected success, got %q", res.Err)
	}

	var endpoints []string
	for _, as := range res.Assets {
		if as.Type != "endpoint" {
			t.Errorf("unexpected asset type %q", as.Type)
		}
		endpoints = append(endpoints, as.Value)
	}
	joined := strings.Join(endpoints, " ")
	// The query link and the GET form should both be discovered as endpoints.
	if !strings.Contains(joined, "/search?q=hello") {
		t.Errorf("expected the /search?q= endpoint; got %v", endpoints)
	}
	if !strings.Contains(joined, "/lookup?") || !strings.Contains(joined, "id=") || !strings.Contains(joined, "ref=") {
		t.Errorf("expected the /lookup form endpoint with id+ref params; got %v", endpoints)
	}
	// Offsite links must NOT be crawled or recorded.
	if strings.Contains(joined, "external.example.com") {
		t.Errorf("offsite host should not be in scope of the crawl: %v", endpoints)
	}
}

func TestWebcrawlDeadHostNotFatal(t *testing.T) {
	res, err := New().Execute(context.Background(), action.Action{ID: "a2", Target: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("connection failure should not be a tool error: %v", err)
	}
	// No pages crawled, but the summary finding is still recorded.
	if res.Success && len(res.Assets) != 0 {
		t.Fatalf("dead host should yield no endpoints, got %d", len(res.Assets))
	}
}

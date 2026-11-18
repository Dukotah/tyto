package evidence

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// roundTripViaRecorder drives one request through a recording client against srv
// and returns the store, the captured IDs, and the response body the caller saw.
func roundTripViaRecorder(t *testing.T, srv *httptest.Server, build func(context.Context) *http.Request) (*MemStore, []string, string) {
	t.Helper()
	store := NewMemStore()
	client := WrapClient(srv.Client(), store)

	cap := &Capture{}
	ctx := WithCapture(context.Background(), cap)
	resp, err := client.Do(build(ctx))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return store, cap.IDs(), string(body)
}

func TestRoundTripperRecordsAndAssociates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		if string(reqBody) != "ping" {
			t.Errorf("server saw request body %q, want the body intact", reqBody)
		}
		w.Header().Set("X-Demo", "yes")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "pong")
	}))
	defer srv.Close()

	store, ids, body := roundTripViaRecorder(t, srv, func(ctx context.Context) *http.Request {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/probe", strings.NewReader("ping"))
		return req
	})

	// Caller still reads the real response body.
	if body != "pong" {
		t.Fatalf("caller body = %q, want %q", body, "pong")
	}
	if len(ids) != 1 {
		t.Fatalf("captured %d evidence IDs, want 1", len(ids))
	}

	rec, ok := store.Get(ids[0])
	if !ok {
		t.Fatalf("stored record %q not retrievable", ids[0])
	}
	if rec.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", rec.Method)
	}
	if rec.Status != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Status, http.StatusTeapot)
	}
	if rec.RequestBody != "ping" {
		t.Errorf("request body = %q, want %q", rec.RequestBody, "ping")
	}
	if rec.ResponseBody != "pong" {
		t.Errorf("response body = %q, want %q", rec.ResponseBody, "pong")
	}
	if got := rec.ResponseHeaders.Get("X-Demo"); got != "yes" {
		t.Errorf("response header X-Demo = %q, want %q", got, "yes")
	}

	// Associate the evidence with a finding by its existing ID and read it back.
	const findingID = "HTTP-a1"
	store.Associate(findingID, ids...)
	got := store.For(findingID)
	if len(got) != 1 {
		t.Fatalf("For(%q) returned %d records, want 1", findingID, len(got))
	}
	if got[0].FindingID != findingID {
		t.Errorf("record FindingID = %q, want %q", got[0].FindingID, findingID)
	}
	if got[0].EvidenceID != ids[0] {
		t.Errorf("record EvidenceID = %q, want %q", got[0].EvidenceID, ids[0])
	}
}

func TestRoundTripperRedactsSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=supersecret; Path=/")
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	store, ids, _ := roundTripViaRecorder(t, srv, func(ctx context.Context) *http.Request {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer super-secret-token")
		req.Header.Set("Cookie", "sid=abc123")
		req.Header.Set("X-Api-Key", "key-should-not-appear")
		req.Header.Set("X-Safe", "keep-me")
		return req
	})
	if len(ids) != 1 {
		t.Fatalf("captured %d IDs, want 1", len(ids))
	}
	rec, _ := store.Get(ids[0])

	for _, h := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if v := rec.RequestHeaders.Get(h); v != redactedValue {
			t.Errorf("request header %s = %q, want %q", h, v, redactedValue)
		}
	}
	if v := rec.RequestHeaders.Get("X-Safe"); v != "keep-me" {
		t.Errorf("non-sensitive header X-Safe = %q, want %q", v, "keep-me")
	}
	if v := rec.ResponseHeaders.Get("Set-Cookie"); v != redactedValue {
		t.Errorf("response Set-Cookie = %q, want %q", v, redactedValue)
	}
	// No secret value should survive anywhere in the stored record's headers.
	for _, secret := range []string{"super-secret-token", "abc123", "key-should-not-appear", "supersecret"} {
		for _, hdr := range []http.Header{rec.RequestHeaders, rec.ResponseHeaders} {
			for k, vs := range hdr {
				for _, v := range vs {
					if strings.Contains(v, secret) {
						t.Errorf("secret %q leaked into header %s", secret, k)
					}
				}
			}
		}
	}
}

func TestAssociateIgnoresUnknownAndDuplicate(t *testing.T) {
	store := NewMemStore()
	id := store.Put(Record{Method: "GET", URL: "http://x", Status: 200})

	store.Associate("F-1", id, id, "EV-does-not-exist", "")
	got := store.For("F-1")
	if len(got) != 1 {
		t.Fatalf("For(F-1) = %d records, want 1 (dup/unknown/empty dropped)", len(got))
	}
	if store.For("F-none") != nil {
		t.Errorf("For on a finding with no evidence should be nil")
	}
}

func TestBodyTruncation(t *testing.T) {
	big := strings.Repeat("A", maxBodyBytes+100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, big)
	}))
	defer srv.Close()

	store, ids, _ := roundTripViaRecorder(t, srv, func(ctx context.Context) *http.Request {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		return req
	})
	rec, _ := store.Get(ids[0])
	if !rec.ResponseTruncated {
		t.Errorf("expected ResponseTruncated = true for an oversized body")
	}
	if len(rec.ResponseBody) != maxBodyBytes {
		t.Errorf("response body len = %d, want cap %d", len(rec.ResponseBody), maxBodyBytes)
	}
}

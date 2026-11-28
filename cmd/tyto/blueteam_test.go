package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/attack"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/tool"
)

// Every planner-selectable tool must either carry an ATT&CK mapping or be on the
// explicit unmapped list — so a newly added tool can't silently fall out of the
// purple-team timeline and detection scoring.
func TestEveryToolHasAttackMapping(t *testing.T) {
	unmapped := map[string]bool{}
	for _, n := range attack.Unmapped() {
		unmapped[n] = true
	}
	registered := map[string]bool{}
	for _, name := range defaultRegistry().Names() {
		registered[name] = true
		mp, ok := attack.ForTool(name)
		switch {
		case ok && unmapped[name]:
			t.Errorf("tool %q is both mapped and listed as unmapped", name)
		case !ok && !unmapped[name]:
			t.Errorf("tool %q has no ATT&CK mapping: add it to internal/attack (or to attack.Unmapped)", name)
		case ok && len(mp.Techniques) == 0:
			t.Errorf("tool %q maps to no technique", name)
		case ok && !mp.OffTarget && len(mp.Telemetry) == 0:
			t.Errorf("tool %q touches the target but lists no expected telemetry", name)
		}
	}
	for _, name := range attack.Tools() {
		if !registered[name] {
			t.Errorf("attack mapping for %q matches no registered tool (stale or misspelled)", name)
		}
	}
}

// Any tool holding an *http.Client must expose the transport seam, or its
// requests would go out without the engagement marker.
func TestHTTPToolsExposeTransportSeam(t *testing.T) {
	clientType := reflect.TypeOf(&http.Client{})
	for _, tl := range defaultRegistry().All() {
		v := reflect.ValueOf(tl)
		if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
			continue
		}
		hasClient := false
		for i := 0; i < v.Elem().NumField(); i++ {
			if v.Elem().Type().Field(i).Type == clientType {
				hasClient = true
			}
		}
		if _, ok := tl.(tool.TransportWrapper); hasClient && !ok {
			t.Errorf("tool %q has an *http.Client but does not implement tool.TransportWrapper", tl.Name())
		}
	}
}

func markerEngagement(scopeURL string) *engagement.Engagement {
	return &engagement.Engagement{
		ID: "acme-q1", Client: "Acme",
		Scope: engagement.Scope{InScope: []engagement.Target{{Type: engagement.TargetURL, Value: scopeURL}}},
	}
}

// recorder is an httptest handler that captures the marker header per path.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Header.Get(engagement.DefaultMarkerHeader))
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func TestTrafficMarkerStampsInScopeRequestsOnly(t *testing.T) {
	inScope, outOfScope := &recorder{}, &recorder{}
	in := httptest.NewServer(inScope)
	defer in.Close()
	out := httptest.NewServer(outOfScope)
	defer out.Close()

	eng := markerEngagement(in.URL + "/")
	reg := defaultRegistry()
	rec := applyTrafficMarker(reg, eng)
	if rec["event"] != "traffic_marker" || rec["header"] != engagement.DefaultMarkerHeader || rec["value"] != "acme-q1" {
		t.Fatalf("unexpected audit record: %v", rec)
	}
	if n, _ := rec["tools"].(int); n < 20 {
		t.Fatalf("expected the native HTTP tools to be wired, got %v", rec["tools"])
	}

	wc, _ := reg.Get("webcheck")
	for _, target := range []string{in.URL + "/", out.URL + "/"} {
		if _, err := wc.Execute(context.Background(), action.Action{ID: "t", Tool: "webcheck", Target: target}); err != nil {
			t.Fatal(err)
		}
	}
	got := inScope.all()
	if len(got) == 0 {
		t.Fatal("webcheck sent no request to the in-scope server")
	}
	for _, h := range got {
		if h != "acme-q1" {
			t.Fatalf("in-scope request missing the engagement marker: %q", h)
		}
	}
	// The guard would never let an out-of-scope target run; this asserts the
	// marker's own defense in depth — the engagement id must not leak off-scope.
	for _, h := range outOfScope.all() {
		if h != "" {
			t.Fatalf("out-of-scope request must not carry the marker, got %q", h)
		}
	}
}

func TestTrafficMarkerDisabledAndCustom(t *testing.T) {
	rcv := &recorder{}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	eng := markerEngagement(srv.URL + "/")
	eng.RoE.TrafficMarker.Disabled = true
	reg := defaultRegistry()
	if rec := applyTrafficMarker(reg, eng); rec["event"] != "traffic_marker_disabled" {
		t.Fatalf("disabled marker must be recorded as such: %v", rec)
	}
	wc, _ := reg.Get("webcheck")
	_, _ = wc.Execute(context.Background(), action.Action{ID: "t", Tool: "webcheck", Target: srv.URL + "/"})
	for _, h := range rcv.all() {
		if h != "" {
			t.Fatalf("disabled marker must not be sent, got %q", h)
		}
	}

	eng.RoE.TrafficMarker = engagement.TrafficMarker{Header: "X-Bug-Bounty", Value: "researcher-42"}
	if h, v, ok := eng.Marker(); !ok || h != "X-Bug-Bounty" || v != "researcher-42" {
		t.Fatalf("custom marker not honored: %q %q %v", h, v, ok)
	}
}

func TestTrafficMarkerValidation(t *testing.T) {
	base := `
id: e1
client: c
authorization: {authorized_by: a, agreement_ref: r}
scope: {in_scope: [{type: ip, value: 127.0.0.1}]}
rules_of_engagement:
  max_risk: low
  traffic_marker: {MARKER}
`
	for marker, wantErr := range map[string]bool{
		`header: X-Test, value: ok`:     false,
		`disabled: true`:                false,
		`header: "bad header"`:          true,
		`value: "line\r\nInjected: 1"`:  true,
		`header: "X-Ok", value: "café"`: true,
	} {
		path := t.TempDir() + "/e.yaml"
		if err := os.WriteFile(path, []byte(strings.Replace(base, "{MARKER}", "{"+marker+"}", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := engagement.Load(path)
		if (err != nil) != wantErr {
			t.Errorf("traffic_marker {%s}: err=%v, wantErr=%v", marker, err, wantErr)
		}
	}
}

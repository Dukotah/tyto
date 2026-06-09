package methodology

import (
	"testing"

	"github.com/dukotah/tyto/internal/state"
)

func TestCatalogLoads(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("embedded catalog is empty")
	}
	for _, tt := range All() {
		if tt.ID == "" || tt.Name == "" || tt.Phase == "" {
			t.Errorf("technique missing required fields: %+v", tt)
		}
	}
}

func TestRecommendMapsServicesToTechniques(t *testing.T) {
	assets := []*state.Asset{
		{ID: "h", Type: "host", Value: "h"},
		{ID: "h:80", Type: "service", Value: "h:80", Attrs: map[string]string{"service": "http"}},
		{ID: "h:22", Type: "service", Value: "h:22", Attrs: map[string]string{"service": "ssh"}},
	}
	recs := Recommend(assets, nil)

	got := map[string]bool{}
	for _, r := range recs {
		got[r.Technique.ID] = true
	}
	// host -> port scan; http -> fingerprint + hardening; ssh -> enum.
	for _, want := range []string{"host-port-scan", "http-fingerprint", "http-hardening-review", "ssh-enum"} {
		if !got[want] {
			t.Errorf("expected recommendation %q; got %v", want, got)
		}
	}
}

func TestRecommendFiltersUnavailableTools(t *testing.T) {
	assets := []*state.Asset{{ID: "h:80", Type: "service", Value: "h:80", Attrs: map[string]string{"service": "http"}}}
	// Only portscan is available; httpprobe/webcheck are not -> their techniques drop.
	recs := Recommend(assets, map[string]bool{"portscan": true})
	for _, r := range recs {
		if r.Technique.Tool == "httpprobe" || r.Technique.Tool == "webcheck" {
			t.Errorf("technique %q with unavailable tool %q should be filtered", r.Technique.ID, r.Technique.Tool)
		}
	}
}

func TestRecommendDeterministicOrder(t *testing.T) {
	assets := []*state.Asset{
		{ID: "b:80", Type: "service", Value: "b:80", Attrs: map[string]string{"service": "http"}},
		{ID: "a:80", Type: "service", Value: "a:80", Attrs: map[string]string{"service": "http"}},
	}
	r1 := Recommend(assets, nil)
	r2 := Recommend(assets, nil)
	if len(r1) != len(r2) || len(r1) == 0 {
		t.Fatalf("unexpected recommendation counts %d/%d", len(r1), len(r2))
	}
	for i := range r1 {
		if r1[i].Target != r2[i].Target || r1[i].Technique.ID != r2[i].Technique.ID {
			t.Fatal("Recommend is not deterministic")
		}
	}
	// sorted by target: a:80 before b:80
	if r1[0].Target != "a:80" {
		t.Fatalf("recommendations not sorted by target: first=%s", r1[0].Target)
	}
}

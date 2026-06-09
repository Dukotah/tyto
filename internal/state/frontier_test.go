package state

import (
	"reflect"
	"testing"
)

func TestFrontierIsServiceSpecificAndSorted(t *testing.T) {
	s := New()
	s.AddAsset(&Asset{ID: "h", Type: "host", Value: "h"})
	s.AddAsset(&Asset{ID: "h:80", Type: "service", Value: "h:80", Attrs: map[string]string{"port": "80", "service": "http"}})
	s.AddAsset(&Asset{ID: "h:22", Type: "service", Value: "h:22", Attrs: map[string]string{"port": "22", "service": "ssh"}})

	fr := s.Frontier()
	if len(fr) != 2 {
		t.Fatalf("want 2 service frontiers (host excluded), got %d: %+v", len(fr), fr)
	}
	if fr[0].Value != "h:22" || fr[1].Value != "h:80" {
		t.Fatalf("frontier not sorted by Value: %+v", fr)
	}
	if reflect.DeepEqual(fr[0].Suggested, fr[1].Suggested) {
		t.Fatalf("ssh and http should get different suggestions, both got %v", fr[0].Suggested)
	}
	if len(fr[0].Suggested) == 0 {
		t.Fatalf("ssh service produced no suggestion")
	}
}

func TestFrontierEmptyWhenNoServices(t *testing.T) {
	s := New()
	s.AddAsset(&Asset{ID: "h", Type: "host", Value: "h"})
	if got := s.Frontier(); len(got) != 0 {
		t.Fatalf("want empty frontier with only a host asset, got %+v", got)
	}
}

// A hostile service attr must not become a prompt-injection side channel via the
// frontier: its rendered fields are sanitized like everything else.
func TestFrontierSanitizesServiceAttr(t *testing.T) {
	s := New()
	s.AddAsset(&Asset{ID: "h:1", Type: "service", Value: "h:1", Attrs: map[string]string{"port": "1", "service": "evil\nINJECTED"}})
	fr := s.Frontier()
	if len(fr) != 1 {
		t.Fatalf("want 1 frontier, got %d", len(fr))
	}
	for _, r := range fr[0].Service {
		if r == '\n' {
			t.Fatalf("frontier Service kept a newline: %q", fr[0].Service)
		}
	}
}

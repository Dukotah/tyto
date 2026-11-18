package state

import "testing"

// nodeByKind returns the first graph node of the given kind whose Value matches,
// or nil.
func nodeByKind(s *State, kind AssetKind, value string) *GraphNode {
	for _, n := range s.Graph() {
		if n.Kind == kind && n.Value == value {
			return n
		}
	}
	return nil
}

func TestObserveDedupsAndNormalizes(t *testing.T) {
	tests := []struct {
		name      string
		kind      AssetKind
		values    []string // observed in sequence; all should collapse to one node
		wantValue string
	}{
		{"endpoint case + default port", KindEndpoint,
			[]string{"https://API.Example.com/login", "https://api.example.com/login"},
			"https://api.example.com/login"},
		{"host trailing dot", KindSubdomain,
			[]string{"api.example.com.", "api.example.com"}, "api.example.com"},
		{"service host case", KindService,
			[]string{"HOST.example.com:443", "host.example.com:443"}, "host.example.com:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			var first *GraphNode
			for i, v := range tt.values {
				n, isNew := s.Observe(Observation{Kind: tt.kind, Value: v})
				if n == nil {
					t.Fatalf("Observe(%q) returned nil node", v)
				}
				if i == 0 {
					first = n
					if !isNew {
						t.Errorf("first Observe(%q) should be new", v)
					}
				} else if isNew {
					t.Errorf("Observe(%q) created a duplicate instead of deduping", v)
				} else if n.Key != first.Key {
					t.Errorf("Observe(%q) key %q != first key %q", v, n.Key, first.Key)
				}
			}
			if nodeByKind(s, tt.kind, tt.wantValue) == nil {
				t.Errorf("normalized node %q %q not found; graph=%+v", tt.kind, tt.wantValue, s.Graph())
			}
		})
	}
}

func TestObserveBuildsParentChain(t *testing.T) {
	s := New()
	// A single endpoint observation must auto-create its whole ancestor chain:
	// endpoint -> service -> subdomain -> root_domain.
	ep, isNew := s.Observe(Observation{Kind: KindEndpoint, Value: "https://api.example.com/admin"})
	if !isNew || ep == nil {
		t.Fatalf("endpoint observe: isNew=%v node=%v", isNew, ep)
	}

	svc := nodeByKind(s, KindService, "api.example.com:443")
	sub := nodeByKind(s, KindSubdomain, "api.example.com")
	root := nodeByKind(s, KindRootDomain, "example.com")
	if svc == nil || sub == nil || root == nil {
		t.Fatalf("ancestor chain incomplete: svc=%v sub=%v root=%v\ngraph=%+v", svc, sub, root, s.Graph())
	}

	if ep.ParentKey != svc.Key {
		t.Errorf("endpoint parent = %q, want service %q", ep.ParentKey, svc.Key)
	}
	if svc.ParentKey != sub.Key {
		t.Errorf("service parent = %q, want subdomain %q", svc.ParentKey, sub.Key)
	}
	if sub.ParentKey != root.Key {
		t.Errorf("subdomain parent = %q, want root %q", sub.ParentKey, root.Key)
	}
	if root.ParentKey != "" {
		t.Errorf("root parent = %q, want empty", root.ParentKey)
	}
}

func TestObserveServiceOnIP(t *testing.T) {
	s := New()
	svc, _ := s.Observe(Observation{Kind: KindService, Value: "203.0.113.10:22"})
	if svc == nil {
		t.Fatal("service observe returned nil")
	}
	ip := nodeByKind(s, KindIP, "203.0.113.10")
	if ip == nil {
		t.Fatalf("ip ancestor not created: graph=%+v", s.Graph())
	}
	if svc.ParentKey != ip.Key {
		t.Errorf("service parent = %q, want ip %q", svc.ParentKey, ip.Key)
	}
	if ip.ParentKey != "" {
		t.Errorf("bare ip parent = %q, want empty (no host hint)", ip.ParentKey)
	}
}

// AddAsset mirrors the flat asset into the graph: the program, not the caller,
// classifies "host"/"domain" into the right hierarchy level.
func TestAddAssetMirrorsIntoGraph(t *testing.T) {
	tests := []struct {
		typ, value string
		wantKind   AssetKind
		wantValue  string
	}{
		{"host", "198.51.100.7", KindIP, "198.51.100.7"},
		{"host", "shop.example.com", KindSubdomain, "shop.example.com"},
		{"domain", "example.com", KindRootDomain, "example.com"},
		{"service", "198.51.100.7:3306", KindService, "198.51.100.7:3306"},
		{"url", "http://example.com/", KindEndpoint, "http://example.com/"},
		{"cidr", "10.0.0.0/24", "", ""}, // unmapped: flat-only, no graph node
	}
	for _, tt := range tests {
		s := New()
		s.AddAsset(&Asset{ID: "x", Type: tt.typ, Value: tt.value})
		if tt.wantKind == "" {
			if len(s.Graph()) != 0 {
				t.Errorf("%s/%s produced graph nodes, want none: %+v", tt.typ, tt.value, s.Graph())
			}
			continue
		}
		if nodeByKind(s, tt.wantKind, tt.wantValue) == nil {
			t.Errorf("%s/%s: want %q node %q; graph=%+v", tt.typ, tt.value, tt.wantKind, tt.wantValue, s.Graph())
		}
	}
}

func TestObserveMergesAttrsKeepingFirst(t *testing.T) {
	s := New()
	s.Observe(Observation{Kind: KindService, Value: "h.example.com:443", Attrs: map[string]string{"product": "nginx"}})
	n, isNew := s.Observe(Observation{Kind: KindService, Value: "h.example.com:443", Attrs: map[string]string{"product": "apache", "version": "2.4"}})
	if isNew {
		t.Fatal("second observe should dedup, not create")
	}
	if n.Attrs["product"] != "nginx" {
		t.Errorf("product = %q, want nginx (first writer wins)", n.Attrs["product"])
	}
	if n.Attrs["version"] != "2.4" {
		t.Errorf("version = %q, want 2.4 (new key merged in)", n.Attrs["version"])
	}
}

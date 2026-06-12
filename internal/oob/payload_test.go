package oob

import (
	"strings"
	"testing"
)

// payloadProbe builds a deterministic Interaction whose Domain/URL/Token are
// distinctive substrings, so containment assertions are unambiguous.
func payloadProbe() Interaction {
	c := New(testConfig())
	return *c.Register("test", "http://target.test/q", "p")
}

// containsAny reports whether s embeds any of the correlation anchors. A valid
// OOB payload must carry at least one of Domain / URL / Token so an inbound Hit
// can be matched back to the probe.
func containsAny(s string, in Interaction) bool {
	return strings.Contains(s, in.Domain) ||
		strings.Contains(s, in.URL) ||
		strings.Contains(s, in.Token)
}

func TestPayloadGenerators(t *testing.T) {
	in := payloadProbe()

	cases := []struct {
		name string
		set  []string
	}{
		{"SSRFTargets", in.SSRFTargets()},
		{"BlindXSS", in.BlindXSS()},
		{"CmdInjection", in.CmdInjection()},
		{"SQLiOOB", in.SQLiOOB()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.set) == 0 {
				t.Fatalf("%s returned no payloads", tc.name)
			}
			seen := make(map[string]bool, len(tc.set))
			for i, p := range tc.set {
				if p == "" {
					t.Errorf("%s[%d] is empty", tc.name, i)
				}
				if !containsAny(p, in) {
					t.Errorf("%s[%d] = %q does not embed Domain/URL/Token %q/%q/%q",
						tc.name, i, p, in.Domain, in.URL, in.Token)
				}
				if seen[p] {
					t.Errorf("%s[%d] = %q is a duplicate within the set", tc.name, i, p)
				}
				seen[p] = true
			}
		})
	}
}

// TestSSRFHasFetchableURL ensures the SSRF set keeps at least one plain http(s)
// fetch form (path-correlated), not only DNS-only host variants.
func TestSSRFHasFetchableURL(t *testing.T) {
	in := payloadProbe()
	var http bool
	for _, p := range in.SSRFTargets() {
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			http = true
			break
		}
	}
	if !http {
		t.Fatalf("SSRFTargets has no http(s) fetch form: %v", in.SSRFTargets())
	}
}

// TestDedupe checks the helper collapses duplicates in first-seen order.
func TestDedupe(t *testing.T) {
	got := dedupe([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedupe len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

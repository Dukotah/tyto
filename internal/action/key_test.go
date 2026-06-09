package action

import "testing"

func TestCanonicalKeyParamOrderStable(t *testing.T) {
	a := Action{Tool: "portscan", Target: "h", Params: map[string]string{"a": "1", "b": "2"}}
	b := Action{Tool: "portscan", Target: "h", Params: map[string]string{"b": "2", "a": "1"}}
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatal("param map order must not change the key")
	}
}

func TestCanonicalKeyNormalizesTarget(t *testing.T) {
	a := Action{Tool: "httpx", Target: "HTTP://Example.com/"}
	b := Action{Tool: "httpx", Target: "http://example.com"}
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatal("equivalent targets must collapse to one key")
	}
}

func TestCanonicalKeyDistinguishes(t *testing.T) {
	base := Action{Tool: "portscan", Target: "h", Params: map[string]string{"ports": "80"}}
	cases := []Action{
		{Tool: "naabu", Target: "h", Params: map[string]string{"ports": "80"}},     // diff tool
		{Tool: "portscan", Target: "h2", Params: map[string]string{"ports": "80"}}, // diff target
		{Tool: "portscan", Target: "h", Params: map[string]string{"ports": "443"}}, // diff value
		{Tool: "portscan", Target: "h"},                                            // no params
	}
	for i, c := range cases {
		if c.CanonicalKey() == base.CanonicalKey() {
			t.Errorf("case %d should differ from base key", i)
		}
	}
}

package main

import "testing"

func TestParsePentestIntent(t *testing.T) {
	cases := []struct {
		msg        string
		wantTarget string
		wantDepth  string
		wantOk     bool
	}{
		{"pentest http://127.0.0.1:8000", "http://127.0.0.1:8000", "scan", true},
		{"scan example.com", "example.com", "scan", true},
		{"pentest 10.0.0.5", "10.0.0.5", "scan", true},
		{"assess 192.168.1.0/24", "192.168.1.0/24", "scan", true},
		{"recon acme.io for subdomains", "acme.io", "recon", true},
		{"pentest the site at https://app.example.com/login", "https://app.example.com/login", "scan", true},
		// Should NOT fast-path — no verb, or no target token:
		{"is rockyou in the wordlists?", "", "", false},
		{"scan the wordlists for passwords", "", "", false},
		{"what should I do next", "", "", false},
		{"pentest", "", "", false},
		{"run uname -a on the box", "", "", false},
	}
	for _, c := range cases {
		target, depth, ok := parsePentestIntent(c.msg)
		if ok != c.wantOk || target != c.wantTarget || (ok && depth != c.wantDepth) {
			t.Errorf("parsePentestIntent(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.msg, target, depth, ok, c.wantTarget, c.wantDepth, c.wantOk)
		}
	}
}

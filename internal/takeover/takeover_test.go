package takeover

import (
	"context"
	"strings"
	"testing"
)

// fakeResolver is a no-network Resolver driven by static maps.
type fakeResolver struct {
	cnames    map[string]string   // host -> CNAME target (empty/absent => no CNAME)
	cnameErrs map[string]error    // host -> error from LookupCNAME
	hosts     map[string][]string // host -> addrs from LookupHost
	hostErrs  map[string]error    // host -> error from LookupHost (e.g. ErrNotFound)
}

func (r fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if err := r.cnameErrs[host]; err != nil {
		return "", err
	}
	c, ok := r.cnames[host]
	if !ok || c == "" {
		// net.Resolver returns the host itself when there is no CNAME.
		return host, nil
	}
	return c, nil
}

func (r fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if err := r.hostErrs[host]; err != nil {
		return nil, err
	}
	if a, ok := r.hosts[host]; ok {
		return a, nil
	}
	return []string{"203.0.113.10"}, nil
}

// fakeFetcher is a no-network Fetcher driven by a static map keyed on host.
type fakeFetcher struct {
	bodies   map[string]string // host -> body
	statuses map[string]int    // host -> status (default 200 if absent but body present)
	errs     map[string]error  // host -> fetch error (unreachable)
}

func (f fakeFetcher) Fetch(_ context.Context, host string) (int, string, error) {
	if err := f.errs[host]; err != nil {
		return 0, "", err
	}
	body, ok := f.bodies[host]
	if !ok {
		return 0, "", errUnreachable
	}
	st := f.statuses[host]
	if st == 0 {
		st = 200
	}
	return st, body, nil
}

type fetchErr string

func (e fetchErr) Error() string { return string(e) }

const errUnreachable = fetchErr("connection refused")

// notFoundErr implements the net.DNSError-style IsNotFound contract.
type notFoundErr struct{ msg string }

func (e notFoundErr) Error() string    { return e.msg }
func (e notFoundErr) IsNotFound() bool { return true }

func TestCheck(t *testing.T) {
	const githubBody = "There isn't a GitHub Pages site here."
	const githubLiveBody = "<html><head><title>My Project</title></head><body>Welcome to my published GitHub Pages site!</body></html>"

	tests := []struct {
		name       string
		host       string
		res        fakeResolver
		fet        fakeFetcher
		wantVuln   bool
		wantSvc    string
		wantReason string // substring expected in Reason (optional)
	}{
		{
			name:     "github.io CNAME + unclaimed body => vulnerable",
			host:     "blog.example.com",
			res:      fakeResolver{cnames: map[string]string{"blog.example.com": "example.github.io"}},
			fet:      fakeFetcher{bodies: map[string]string{"blog.example.com": "<html>" + githubBody + "</html>"}, statuses: map[string]int{"blog.example.com": 404}},
			wantVuln: true,
			wantSvc:  "GitHub Pages",
		},
		{
			name:       "github.io CNAME + real published page => NOT vulnerable (critical FP guard)",
			host:       "blog.example.com",
			res:        fakeResolver{cnames: map[string]string{"blog.example.com": "example.github.io"}},
			fet:        fakeFetcher{bodies: map[string]string{"blog.example.com": githubLiveBody}, statuses: map[string]int{"blog.example.com": 200}},
			wantVuln:   false,
			wantSvc:    "GitHub Pages",
			wantReason: "appears CLAIMED",
		},
		{
			name:     "s3 CNAME + NoSuchBucket => vulnerable",
			host:     "assets.example.com",
			res:      fakeResolver{cnames: map[string]string{"assets.example.com": "my-bucket.s3.amazonaws.com"}},
			fet:      fakeFetcher{bodies: map[string]string{"assets.example.com": "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"}, statuses: map[string]int{"assets.example.com": 404}},
			wantVuln: true,
			wantSvc:  "AWS S3",
		},
		{
			name:       "no CNAME => not vulnerable",
			host:       "www.example.com",
			res:        fakeResolver{},                                                        // LookupCNAME returns host itself
			fet:        fakeFetcher{bodies: map[string]string{"www.example.com": githubBody}}, // even if body matches, no CNAME gate
			wantVuln:   false,
			wantReason: "no CNAME",
		},
		{
			name:       "CNAME to a non-fingerprinted host => not vulnerable",
			host:       "app.example.com",
			res:        fakeResolver{cnames: map[string]string{"app.example.com": "lb-1234.us-east-1.elb.example-cdn.net"}},
			fet:        fakeFetcher{bodies: map[string]string{"app.example.com": githubBody}},
			wantVuln:   false,
			wantReason: "not a fingerprinted",
		},
		{
			name:       "fingerprint body present but CNAME absent => not vulnerable",
			host:       "static.example.com",
			res:        fakeResolver{}, // no CNAME
			fet:        fakeFetcher{bodies: map[string]string{"static.example.com": "NoSuchBucket"}},
			wantVuln:   false,
			wantReason: "no CNAME",
		},
		{
			name:       "fingerprinted CNAME but host unreachable => not vulnerable",
			host:       "old.example.com",
			res:        fakeResolver{cnames: map[string]string{"old.example.com": "ghost-blog.ghost.io"}},
			fet:        fakeFetcher{errs: map[string]error{"old.example.com": errUnreachable}},
			wantVuln:   false,
			wantSvc:    "Ghost",
			wantReason: "unreachable",
		},
		{
			name:     "azure dangling CNAME + NXDOMAIN target => vulnerable via DNS signal",
			host:     "legacy.example.com",
			res:      fakeResolver{cnames: map[string]string{"legacy.example.com": "myapp.azurewebsites.net"}, hostErrs: map[string]error{"myapp.azurewebsites.net": notFoundErr{"lookup myapp.azurewebsites.net: no such host"}}},
			fet:      fakeFetcher{errs: map[string]error{"legacy.example.com": errUnreachable}},
			wantVuln: true,
			wantSvc:  "Azure (cloudapp / trafficmanager / azurewebsites)",
		},
		{
			name:     "azure CNAME but target still resolves => not vulnerable",
			host:     "live.example.com",
			res:      fakeResolver{cnames: map[string]string{"live.example.com": "myapp.azurewebsites.net"}}, // LookupHost succeeds
			fet:      fakeFetcher{errs: map[string]error{"live.example.com": errUnreachable}},
			wantVuln: false,
			wantSvc:  "Azure (cloudapp / trafficmanager / azurewebsites)",
		},
		{
			name:     "shopify CNAME + unclaimed body => vulnerable",
			host:     "shop.example.com",
			res:      fakeResolver{cnames: map[string]string{"shop.example.com": "example.myshopify.com"}},
			fet:      fakeFetcher{bodies: map[string]string{"shop.example.com": "<h1>Sorry, this shop is currently unavailable</h1>"}},
			wantVuln: true,
			wantSvc:  "Shopify",
		},
		{
			name:       "empty host => not vulnerable",
			host:       "   ",
			res:        fakeResolver{},
			fet:        fakeFetcher{},
			wantVuln:   false,
			wantReason: "empty host",
		},
		{
			name:     "url-shaped host is normalized then checked",
			host:     "https://blog.example.com:443/path?q=1",
			res:      fakeResolver{cnames: map[string]string{"blog.example.com": "example.github.io"}},
			fet:      fakeFetcher{bodies: map[string]string{"blog.example.com": githubBody}, statuses: map[string]int{"blog.example.com": 404}},
			wantVuln: true,
			wantSvc:  "GitHub Pages",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := New(tc.res, tc.fet)
			got := e.Check(context.Background(), tc.host, nil, nil)
			if got.Vulnerable != tc.wantVuln {
				t.Fatalf("Vulnerable = %v, want %v (reason: %q)", got.Vulnerable, tc.wantVuln, got.Reason)
			}
			if tc.wantSvc != "" && got.Service != tc.wantSvc {
				t.Errorf("Service = %q, want %q", got.Service, tc.wantSvc)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
			if got.Vulnerable {
				if got.Confidence != ConfidenceHigh {
					t.Errorf("Confidence = %q, want %q for a vulnerable result", got.Confidence, ConfidenceHigh)
				}
				if got.Evidence == "" {
					t.Errorf("vulnerable result must carry Evidence, got empty")
				}
			}
		})
	}
}

func TestCheckAllAndVulnerable(t *testing.T) {
	res := fakeResolver{cnames: map[string]string{
		"vuln.example.com": "example.github.io",
		"safe.example.com": "example.github.io",
		"none.example.com": "", // no CNAME
	}}
	fet := fakeFetcher{bodies: map[string]string{
		"vuln.example.com": "There isn't a GitHub Pages site here.",
		"safe.example.com": "<html>live claimed page</html>",
		"none.example.com": "There isn't a GitHub Pages site here.",
	}}
	e := New(res, fet)
	results := e.CheckAll(context.Background(), []string{"vuln.example.com", "safe.example.com", "none.example.com"})
	if len(results) != 3 {
		t.Fatalf("CheckAll returned %d results, want 3", len(results))
	}
	vuln := Vulnerable(results)
	if len(vuln) != 1 {
		t.Fatalf("Vulnerable filtered to %d, want 1: %+v", len(vuln), vuln)
	}
	if vuln[0].Host != "vuln.example.com" {
		t.Errorf("vulnerable host = %q, want vuln.example.com", vuln[0].Host)
	}
}

func TestStatusBodyGate(t *testing.T) {
	// Netlify fingerprint uses a status-qualified body. A matching body on a 200
	// (claimed) must NOT match; the same phrase on a 404 (unclaimed) must match.
	res := fakeResolver{cnames: map[string]string{
		"a.example.com": "mysite.netlify.app",
		"b.example.com": "mysite.netlify.app",
	}}
	fet := fakeFetcher{
		bodies: map[string]string{
			"a.example.com": "Not Found - Request ID: abc123",
			"b.example.com": "Not Found - Request ID: abc123",
		},
		statuses: map[string]int{
			"a.example.com": 200, // claimed-ish: status does not match the 404 gate
			"b.example.com": 404, // unclaimed
		},
	}
	e := New(res, fet)
	if r := e.Check(context.Background(), "a.example.com", nil, nil); r.Vulnerable {
		t.Errorf("status-qualified body on 200 must NOT be vulnerable, got %+v", r)
	}
	if r := e.Check(context.Background(), "b.example.com", nil, nil); !r.Vulnerable {
		t.Errorf("status-qualified body on 404 must be vulnerable, got %+v", r)
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sentinel", ErrNotFound, true},
		{"dnserror-style", notFoundErr{"no such host"}, true},
		{"textual no such host", fetchErr("lookup x: no such host"), true},
		{"unrelated", fetchErr("connection refused"), false},
		{"servfail not treated as nxdomain", fetchErr("lookup x: server misbehaving"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsNotFound(c.err); got != c.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":                    "example.com",
		"https://blog.example.com/path":  "blog.example.com",
		"blog.example.com:443":           "blog.example.com",
		"http://user:pw@h.example.com/x": "h.example.com",
		"host.example.com.":              "host.example.com",
		"  spaced.example.com  ":         "spaced.example.com",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

package engine

import (
	"net"
	"net/url"
	"strings"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// seedAssets turns the engagement's in-scope targets into the initial asset
// graph BEFORE the first planning cycle. This is the difference between the
// methodology frontier being empty at cycle 1 (so the model free-forms and
// usually never reaches the deep web/service checks) and being fully populated
// (so the deterministic methodology can recommend the whole battery from the
// start).
//
// The key move is emitting a `service` asset with Attrs["service"]="http"/"https"
// for any web target. The methodology catalog gates the entire web-testing
// battery (headers/TLS/CORS/methods/secrets/content-discovery/CVE/nuclei/nikto/
// whatweb/...) on exactly that asset shape — and no recon tool reliably produces
// it for a plain URL or domain, so without seeding those techniques never fire.
//
// Seeded assets are methodology HINTS, not findings: they say "there is probably
// a web service here worth testing", not "this service is confirmed up". If a
// guessed service is down, the tools targeting it simply no-op. httpprobe/
// portscan later emit the authoritative service assets, which dedupe/refine
// these.
func seedAssets(targets []engagement.Target) []state.Asset {
	var assets []state.Asset
	seen := map[string]bool{}
	add := func(a state.Asset) {
		if a.ID == "" || seen[a.ID] {
			return
		}
		seen[a.ID] = true
		assets = append(assets, a)
	}

	// hostAsset emits the right host-flavored asset for a bare hostname/IP so the
	// recon→scan chain (dnsenum/subfinder/portscan/httpprobe) has something to act
	// on in addition to the web service.
	hostAsset := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if net.ParseIP(host) != nil {
			add(state.Asset{ID: "seed:host:" + host, Type: "host", Value: host})
			return
		}
		add(state.Asset{ID: "seed:domain:" + host, Type: "domain", Value: host})
	}

	// webService emits a service asset (the catalog's gate for the web battery)
	// plus the matching host asset. scheme is "http" or "https".
	webService := func(rawURL, scheme, host string) {
		add(state.Asset{
			ID:    "seed:svc:" + rawURL,
			Type:  "service",
			Value: rawURL,
			Attrs: map[string]string{"service": scheme, "seed": "1"},
		})
		hostAsset(host)
	}

	for _, t := range targets {
		v := strings.TrimSpace(t.Value)
		if v == "" {
			continue
		}
		switch t.Type {
		case engagement.TargetURL:
			u, err := url.Parse(v)
			if err != nil || u.Hostname() == "" {
				continue
			}
			scheme := strings.ToLower(u.Scheme)
			if scheme != "http" && scheme != "https" {
				scheme = "https"
			}
			webService(v, scheme, u.Hostname())
		case engagement.TargetDomain:
			// Web-first default: assume an HTTPS service so the full web battery is
			// offered. The recon chain still runs; if HTTPS is down, httpprobe emits
			// the real service asset and the seeded one's tools just no-op.
			webService("https://"+v, "https", v)
		case engagement.TargetIP:
			add(state.Asset{ID: "seed:host:" + v, Type: "host", Value: v})
		case engagement.TargetCIDR:
			// A range isn't a single host; leave expansion to active scanning so we
			// don't fabricate hosts that may not exist.
		}
	}
	return assets
}

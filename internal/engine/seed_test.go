package engine

import (
	"testing"

	"github.com/dukotah/tyto/internal/engagement"
)

// findSeed returns the first seeded asset of the given Type whose Attrs["service"]
// matches svc (svc="" matches any), or nil.
func findSeed(assets []seedAsset, typ, svc string) *seedAsset {
	for i := range assets {
		a := assets[i]
		if a.Type != typ {
			continue
		}
		if svc != "" && a.Attrs["service"] != svc {
			continue
		}
		return &assets[i]
	}
	return nil
}

// seedAsset mirrors the fields of state.Asset we assert on, so the test reads
// clearly without importing the state package's full type machinery.
type seedAsset struct {
	Type, Value string
	Attrs       map[string]string
}

func toSeedAssets(targets []engagement.Target) []seedAsset {
	raw := seedAssets(targets)
	out := make([]seedAsset, len(raw))
	for i, a := range raw {
		out[i] = seedAsset{Type: a.Type, Value: a.Value, Attrs: a.Attrs}
	}
	return out
}

func TestSeedURLTargetUnlocksWebBattery(t *testing.T) {
	got := toSeedAssets([]engagement.Target{{Type: engagement.TargetURL, Value: "https://app.example.com/login"}})

	// The service asset (service=https) is the gate the whole web battery hangs on.
	svc := findSeed(got, "service", "https")
	if svc == nil {
		t.Fatalf("URL target did not seed an https service asset: %+v", got)
	}
	if svc.Value != "https://app.example.com/login" {
		t.Fatalf("service asset value = %q, want the full URL", svc.Value)
	}
	// And a domain asset so the recon chain (dnsenum/subfinder/portscan) has a host.
	if dom := findSeed(got, "domain", ""); dom == nil || dom.Value != "app.example.com" {
		t.Fatalf("URL target did not seed the hostname as a domain asset: %+v", got)
	}
}

func TestSeedDomainTargetSeedsHTTPSService(t *testing.T) {
	got := toSeedAssets([]engagement.Target{{Type: engagement.TargetDomain, Value: "example.com"}})
	if svc := findSeed(got, "service", "https"); svc == nil || svc.Value != "https://example.com" {
		t.Fatalf("domain target should seed an https service for the web battery: %+v", got)
	}
	if dom := findSeed(got, "domain", ""); dom == nil {
		t.Fatalf("domain target should seed a domain asset for recon: %+v", got)
	}
}

func TestSeedIPTargetSeedsHostOnly(t *testing.T) {
	got := toSeedAssets([]engagement.Target{{Type: engagement.TargetIP, Value: "10.0.0.5"}})
	if h := findSeed(got, "host", ""); h == nil || h.Value != "10.0.0.5" {
		t.Fatalf("IP target should seed a host asset, got %+v", got)
	}
	// No fabricated web service for a bare IP — let active scanning find services.
	if svc := findSeed(got, "service", ""); svc != nil {
		t.Fatalf("IP target should NOT fabricate a service asset, got %+v", got)
	}
}

func TestSeedCIDRTargetSeedsCIDRAsset(t *testing.T) {
	// A CIDR seeds a single `cidr` asset (NOT fabricated hosts) so the netsweep
	// technique can do host discovery and emit the authoritative per-host assets.
	got := toSeedAssets([]engagement.Target{{Type: engagement.TargetCIDR, Value: "10.0.0.0/24"}})
	if len(got) != 1 || got[0].Type != "cidr" || got[0].Value != "10.0.0.0/24" {
		t.Fatalf("CIDR should seed exactly one cidr asset, got %+v", got)
	}
	// And it must NOT fabricate host assets that may not exist.
	if h := findSeed(got, "host", ""); h != nil {
		t.Fatalf("CIDR must not fabricate host assets, got %+v", got)
	}
}

package hostheader

import "testing"

const marker = "tyto-hh-7.example"

func TestClassifyBodyReflectionInHref(t *testing.T) {
	base := `<a href="https://real.example/login">login</a>`
	inj := `<a href="https://` + marker + `/login">login</a>`
	r := classify(base, "", inj, "", marker, false)
	if r.kind != reflectBody {
		t.Fatalf("expected reflectBody, got %v", r.kind)
	}
	if r.evidence == "" {
		t.Errorf("expected non-empty evidence")
	}
}

func TestClassifyMarkerOnlyInBaselineRefutes(t *testing.T) {
	// Marker present in baseline => caller passes baselineHasMarker=true and we
	// must refuse to attribute reflection to our injection.
	body := `<a href="https://` + marker + `/">x</a>`
	r := classify(body, "", body, "", marker, true)
	if r.kind != reflectNone {
		t.Fatalf("expected refute (reflectNone) when baseline already has marker, got %v", r.kind)
	}
}

func TestClassifyMarkerInBaselineNotInInjectedRefutes(t *testing.T) {
	base := `canonical https://` + marker + `/`
	inj := `<a href="https://real.example/">x</a>`
	r := classify(base, "", inj, "", marker, false)
	if r.kind != reflectNone {
		t.Fatalf("expected refute when marker absent from injected body, got %v", r.kind)
	}
}

func TestClassifyLocationReflectionIsHigh(t *testing.T) {
	r := classify("", "/dashboard", "", "https://"+marker+"/reset?token=abc", marker, false)
	if r.kind != reflectLocation {
		t.Fatalf("expected reflectLocation, got %v", r.kind)
	}
}

func TestClassifyLocationPresentInBaselineRefutes(t *testing.T) {
	r := classify("", "https://"+marker+"/x", "", "https://"+marker+"/x", marker, false)
	if r.kind != reflectNone {
		t.Fatalf("expected refute when marker already in baseline Location, got %v", r.kind)
	}
}

func TestLocationProtocolRelativeReflection(t *testing.T) {
	if !locationReflectsHost("//"+marker+"/path", marker) {
		t.Errorf("expected protocol-relative Location to reflect host")
	}
	if locationReflectsHost("/relative/path", marker) {
		t.Errorf("a relative path must not be treated as a host reflection")
	}
}

func TestBodyReflectsHostBoundary(t *testing.T) {
	// A look-alike host with the marker as a sub-label must NOT match — host
	// parsing, not substring, is the guard against this.
	if bodyReflectsHost(`https://`+marker+`.attacker.test/`, marker) {
		t.Errorf("sub-label look-alike host must not match marker")
	}
	// Marker only as a path segment must not match either.
	if bodyReflectsHost(`https://real.example/`+marker+`/`, marker) {
		t.Errorf("marker in a path segment must not match")
	}
	// Genuine absolute URL with marker as the host must match.
	if !bodyReflectsHost(`<script src="https://`+marker+`/a.js">`, marker) {
		t.Errorf("genuine absolute-URL host should match")
	}
	// Protocol-relative src must match.
	if !bodyReflectsHost(`<img src="//`+marker+`/p.png">`, marker) {
		t.Errorf("protocol-relative host should match")
	}
	// With a port the host (sans port) must still match.
	if !bodyReflectsHost(`href="https://`+marker+`:8443/x"`, marker) {
		t.Errorf("host with port should still match on hostname")
	}
}

func TestRedactBoundsAndCollapses(t *testing.T) {
	in := "a\n   b\t c"
	if got := redact(in); got != "a b c" {
		t.Errorf("expected whitespace collapse, got %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	if got := redact(string(long)); len([]rune(got)) > 201 {
		t.Errorf("redact did not bound length: %d runes", len([]rune(got)))
	}
}

package validate

import (
	"context"
	"testing"

	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/takeover"
)

type fakeRes struct{ cname string }

func (f fakeRes) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }
func (f fakeRes) LookupHost(context.Context, string) ([]string, error) {
	return []string{"203.0.113.5"}, nil
}

type fakeFet struct{ body string }

func (f fakeFet) Fetch(context.Context, string) (int, string, error) { return 200, f.body, nil }

func tkVerifier(cname, body string) subTakeoverVerifier {
	return subTakeoverVerifier{eng: takeover.New(fakeRes{cname: cname}, fakeFet{body: body})}
}

// A double-gated takeover (CNAME to provider + unclaimed body) confirms.
func TestSubTakeoverVerifier_ConfirmsDoubleGated(t *testing.T) {
	v := tkVerifier("victim.github.io", "There isn't a GitHub Pages site here.")
	f := state.Finding{Title: "Possible subdomain takeover (GitHub Pages)", Target: "sub.example.com"}
	vd := v.verify(context.Background(), nil, f)
	if vd.Status != StatusConfirmed {
		t.Fatalf("want confirmed, got %s (%s)", vd.Status, vd.Reason)
	}
}

// A claimed provider page (CNAME but no unclaimed signal) is REFUTED — the gate
// stops a stale/fixed takeover candidate from reaching the submit body.
func TestSubTakeoverVerifier_RefutesClaimed(t *testing.T) {
	v := tkVerifier("victim.github.io", "<html>my live claimed site</html>")
	f := state.Finding{Title: "Possible subdomain takeover (GitHub Pages)", Target: "sub.example.com"}
	if vd := v.verify(context.Background(), nil, f); vd.Status == StatusConfirmed {
		t.Fatalf("claimed page must not confirm; got %s", vd.Status)
	}
}

// A body-only fingerprint with no provider CNAME is REFUTED (no false confirm).
func TestSubTakeoverVerifier_RefutesBodyOnly(t *testing.T) {
	v := tkVerifier("", "blog post mentioning NoSuchBucket")
	f := state.Finding{Title: "Possible subdomain takeover (AWS S3)", Target: "sub.example.com"}
	if vd := v.verify(context.Background(), nil, f); vd.Status == StatusConfirmed {
		t.Fatalf("body-only match must not confirm; got %s", vd.Status)
	}
}

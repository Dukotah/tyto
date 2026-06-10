// Package tlscheck inspects the TLS posture of an authorized HTTPS service:
// support for deprecated protocol versions (TLS 1.0/1.1) and certificate
// problems (expired, not-yet-valid, self-signed, hostname mismatch). Pure
// stdlib crypto/tls — offline, no dependencies.
package tlscheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{}

func New() *Tool { return &Tool{} }

func (t *Tool) Name() string              { return "tlscheck" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	addr, host := dialTarget(a.Target)

	// Primary handshake (don't verify — we want to inspect a bad cert too).
	conn, err := dial(ctx, addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		res.Err = err.Error()
		res.Output = fmt.Sprintf("%s: no TLS (%v)", addr, err)
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}
	cs := conn.ConnectionState()
	_ = conn.Close()

	now := time.Now()
	add := func(sev state.Severity, title, detail, evidence string) {
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("TLS-%s-%d", a.ID, len(res.Findings)), Title: title, Severity: sev,
			Target: addr, Description: detail, Evidence: evidence, Tool: t.Name(), Validated: true,
		})
	}

	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		switch {
		case now.After(c.NotAfter):
			add(state.SeverityHigh, "Expired TLS certificate", "the server certificate is past its validity window", "NotAfter "+c.NotAfter.Format(time.RFC3339))
		case now.Before(c.NotBefore):
			add(state.SeverityMedium, "TLS certificate not yet valid", "the server certificate's validity window has not started", "NotBefore "+c.NotBefore.Format(time.RFC3339))
		}
		if c.Issuer.String() == c.Subject.String() {
			add(state.SeverityLow, "Self-signed TLS certificate", "the certificate is self-signed (not chained to a trusted CA)", "subject == issuer: "+c.Subject.String())
		}
		if c.VerifyHostname(host) != nil {
			add(state.SeverityMedium, "TLS certificate hostname mismatch", "the certificate is not valid for the requested host", "host "+host+" not in cert SANs")
		}
	}

	// Probe for deprecated protocol support (TLS 1.0/1.1).
	if weak, err := dial(ctx, addr, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		_ = weak.Close()
		add(state.SeverityMedium, "Deprecated TLS version supported", "the server accepts TLS 1.0/1.1, which are deprecated and insecure", "handshake succeeded with MaxVersion=TLS1.1")
	}

	res.Success = true
	res.Output = fmt.Sprintf("%s: TLS %s, %d issue(s)", addr, tlsVersionName(cs.Version), len(res.Findings))
	res.FinishedAt = time.Now().UTC()
	return res, nil
}

func dial(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 6 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// dialTarget resolves a target to a host:port to dial and the bare host for cert
// verification. Defaults to :443 when no port is present.
func dialTarget(target string) (addr, host string) {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		return net.JoinHostPort(h, p), h
	}
	return net.JoinHostPort(t, "443"), t
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}

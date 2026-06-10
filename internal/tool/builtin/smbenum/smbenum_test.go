package smbenum

import (
	"context"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/state"
)

// TestExecute_GracefulDegrade exercises the common path on a box WITHOUT any
// SMB enumeration tool installed (CI/dev). Execute must succeed and emit the
// single "No SMB enumeration tool installed" info finding rather than erroring.
//
// NOTE: the live shell-out path is NOT exercised here — by design there is no
// nxc/netexec/crackmapexec present, so detectTool() returns "".
func TestExecute_GracefulDegrade(t *testing.T) {
	if detectTool() != "" {
		t.Skip("an SMB enumeration tool is installed; graceful-degrade path not applicable")
	}

	tool := New()
	res, err := tool.Execute(context.Background(), action.Action{
		ID:     "a1",
		Tool:   "smbenum",
		Target: "10.0.0.5",
	})
	if err != nil {
		t.Fatalf("Execute returned error on degrade path: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true on graceful degrade, got false")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != state.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", f.Severity)
	}
	if !strings.Contains(f.Title, "No SMB enumeration tool installed") {
		t.Errorf("unexpected finding title: %q", f.Title)
	}
}

// sampleNetExec is a captured NetExec `smb <ip> --shares` output (anonymized).
const sampleNetExec = `SMB         10.0.0.5        445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB         10.0.0.5        445    DC01             [+] corp.local\svc_scan:Password123
SMB         10.0.0.5        445    DC01             Share           Permissions     Remark
SMB         10.0.0.5        445    DC01             -----           -----------     ------
SMB         10.0.0.5        445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         10.0.0.5        445    DC01             IPC$            READ            Remote IPC
SMB         10.0.0.5        445    DC01             Public                          `

func TestParseSMB(t *testing.T) {
	findings, assets := parseSMB(sampleNetExec)

	// Three share rows: ADMIN$, IPC$, Public. Banner/auth/header/separator
	// lines must be skipped.
	if len(findings) != 3 {
		t.Fatalf("expected 3 share findings, got %d: %+v", len(findings), findings)
	}

	byTitle := map[string]state.Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
	}

	admin, ok := byTitle["SMB share: ADMIN$ (READ,WRITE)"]
	if !ok {
		t.Fatalf("missing ADMIN$ finding; got titles: %v", titles(findings))
	}
	if admin.Severity != state.SeverityLow {
		t.Errorf("ADMIN$ (WRITE) should be SeverityLow, got %v", admin.Severity)
	}

	ipc, ok := byTitle["SMB share: IPC$ (READ)"]
	if !ok {
		t.Fatalf("missing IPC$ finding; got titles: %v", titles(findings))
	}
	if ipc.Severity != state.SeverityInfo {
		t.Errorf("IPC$ (READ-only) should be SeverityInfo, got %v", ipc.Severity)
	}

	// Host asset.
	if len(assets) != 1 {
		t.Fatalf("expected 1 host asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "service" || a.Value != "10.0.0.5:445" {
		t.Errorf("unexpected asset: %+v", a)
	}
	if a.Attrs["hostname"] != "DC01" {
		t.Errorf("expected hostname DC01, got %q", a.Attrs["hostname"])
	}
	if a.Attrs["service"] != "smb" {
		t.Errorf("expected service smb, got %q", a.Attrs["service"])
	}
}

func titles(fs []state.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

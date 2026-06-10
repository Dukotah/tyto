package adapter

import (
	"context"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	// "go" is on PATH during tests; a random name is not.
	if got := Detect("definitely-not-a-real-binary-xyz123", "go"); got != "go" {
		t.Errorf("Detect picked %q, want go", got)
	}
	if got := Detect("definitely-not-a-real-binary-xyz123"); got != "" {
		t.Errorf("Detect found a missing binary: %q", got)
	}
}

func TestRunCapturesAndCaps(t *testing.T) {
	out, err := Run(context.Background(), "go", []string{"version"}, 0)
	if err != nil {
		t.Fatalf("Run go version: %v", err)
	}
	if !strings.Contains(out, "go") {
		t.Errorf("output %q missing 'go'", out)
	}
	// Cap: ask for only 4 bytes back.
	capped, _ := Run(context.Background(), "go", []string{"version"}, 4)
	if len(capped) > 4 {
		t.Errorf("cap not honored: got %d bytes", len(capped))
	}
}

func TestMissing(t *testing.T) {
	f := Missing("nmap", "10.0.0.1", "apt install nmap")
	if f.Severity != 0 && f.Severity.String() != "info" {
		t.Errorf("Missing severity = %v, want info", f.Severity)
	}
	if !strings.Contains(f.Description, "apt install nmap") {
		t.Errorf("Missing description lacks install hint: %q", f.Description)
	}
	if f.Validated {
		t.Error("Missing finding should not be Validated")
	}
}

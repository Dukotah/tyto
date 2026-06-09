package main

import (
	"bytes"
	"strings"
	"testing"
)

func execute(args ...string) (string, error) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestVersionCmd(t *testing.T) {
	out, err := execute("version")
	if err != nil || !strings.HasPrefix(out, "tyto ") {
		t.Fatalf("version: out=%q err=%v", out, err)
	}
}

func TestToolsCmd(t *testing.T) {
	out, err := execute("tools")
	if err != nil || !strings.Contains(out, "portscan") {
		t.Fatalf("tools: out=%q err=%v", out, err)
	}
}

func TestEngagementValidate(t *testing.T) {
	out, err := execute("engagement", "validate", "../../configs/engagement.example.yaml")
	if err != nil {
		t.Fatalf("validate errored: %v", err)
	}
	if !strings.Contains(out, "OK:") || !strings.Contains(out, "max_risk=") {
		t.Fatalf("validate output unexpected: %q", out)
	}
}

func TestEngagementValidateArgsRequired(t *testing.T) {
	if _, err := execute("engagement", "validate"); err == nil {
		t.Fatal("validate without a file arg should error")
	}
}

func TestRunRequiresEngagement(t *testing.T) {
	_, err := execute("run")
	if err == nil {
		t.Fatal("run without --engagement should error")
	}
}

func TestAuthorizeKeygen(t *testing.T) {
	out, err := execute("authorize", "keygen")
	if err != nil || !strings.Contains(out, "client_public_key:") || !strings.Contains(out, "private_key:") {
		t.Fatalf("keygen: out=%q err=%v", out, err)
	}
}

func TestUnknownCommandErrors(t *testing.T) {
	if _, err := execute("bogus"); err == nil {
		t.Fatal("unknown command should error")
	}
}

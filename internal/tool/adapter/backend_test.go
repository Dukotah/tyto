package adapter

import (
	"reflect"
	"testing"
)

func TestConfigureAndWrap(t *testing.T) {
	t.Cleanup(func() { execPrefix = nil }) // don't leak backend into other tests

	// Host backend: identity.
	if err := Configure(""); err != nil {
		t.Fatalf("Configure(host): %v", err)
	}
	if Backend() != "" {
		t.Errorf("host Backend() = %q, want empty", Backend())
	}
	if n, a := wrap("nmap", []string{"-sS", "x"}); n != "nmap" || !reflect.DeepEqual(a, []string{"-sS", "x"}) {
		t.Errorf("host wrap = %q %v, want identity", n, a)
	}

	// WSL backend: every command is prefixed with `wsl -d <distro> --`.
	if err := Configure("wsl:kali-linux"); err != nil {
		t.Fatalf("Configure(wsl): %v", err)
	}
	if Backend() != "wsl -d kali-linux" {
		t.Errorf("Backend() = %q", Backend())
	}
	n, a := wrap("nmap", []string{"-sS", "x"})
	want := []string{"-d", "kali-linux", "--", "nmap", "-sS", "x"}
	if n != "wsl" || !reflect.DeepEqual(a, want) {
		t.Errorf("wsl wrap = %q %v, want wsl %v", n, a, want)
	}
	// The shell tool's `bash -lc <cmd>` must wrap correctly too.
	n, a = wrap("bash", []string{"-lc", "ls /usr/share/wordlists"})
	want = []string{"-d", "kali-linux", "--", "bash", "-lc", "ls /usr/share/wordlists"}
	if n != "wsl" || !reflect.DeepEqual(a, want) {
		t.Errorf("wsl bash wrap = %q %v, want wsl %v", n, a, want)
	}
}

func TestConfigureRejectsGarbage(t *testing.T) {
	t.Cleanup(func() { execPrefix = nil })
	if err := Configure("docker:foo"); err == nil {
		t.Error("expected error for unknown backend")
	}
	if err := Configure("wsl:"); err == nil {
		t.Error("expected error for empty distro")
	}
}

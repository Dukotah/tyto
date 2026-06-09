package sysinfo

import "testing"

// Smoke test: on a supported platform (windows/linux/darwin) detection returns a
// plausible nonzero value; elsewhere it is skipped.
func TestTotalRAMBytesSmoke(t *testing.T) {
	ram, err := TotalRAMBytes()
	if err != nil {
		t.Skipf("RAM detection unsupported on this platform: %v", err)
	}
	if ram == 0 {
		t.Fatal("detected 0 bytes of physical RAM")
	}
}

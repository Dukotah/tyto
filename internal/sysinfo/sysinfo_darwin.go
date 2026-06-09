//go:build darwin

package sysinfo

import (
	"encoding/binary"
	"syscall"
)

// totalRAM reads the 64-bit hw.memsize sysctl. Best-effort and pure-Go: if the
// raw value comes back an unexpected size it is zero-padded, which only ever
// under-reports (a safe direction — picks a smaller model).
func totalRAM() (uint64, error) {
	s, err := syscall.Sysctl("hw.memsize")
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 8)
	copy(buf, []byte(s))
	return binary.LittleEndian.Uint64(buf), nil
}

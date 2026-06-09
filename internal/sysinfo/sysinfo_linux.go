//go:build linux

package sysinfo

import "syscall"

func totalRAM() (uint64, error) {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0, err
	}
	return uint64(si.Totalram) * uint64(si.Unit), nil
}

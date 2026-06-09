//go:build !windows && !linux && !darwin

package sysinfo

func totalRAM() (uint64, error) { return 0, ErrUnsupported }

// Package sysinfo reports host facts (currently total physical RAM) used to pick
// sensible defaults. Detection is best-effort and pure-Go (CGO_ENABLED=0): a
// caller treats a non-nil error as "unknown" and falls back to a safe default
// rather than failing.
package sysinfo

import "errors"

// ErrUnsupported is returned on platforms where RAM detection isn't implemented.
var ErrUnsupported = errors.New("sysinfo: RAM detection unsupported on this platform")

// TotalRAMBytes returns total physical RAM in bytes.
func TotalRAMBytes() (uint64, error) { return totalRAM() }

// Package adapter is shared plumbing for tyto tools that shell out to external
// pentest binaries (nmap, nuclei, sqlmap, ...). It standardizes three things
// every adapter needs: detecting the binary on PATH, running it bounded by the
// context + an output cap (no shell — args are passed as a slice, so target
// values can't inject), and degrading gracefully (an Info finding) when the
// binary isn't installed. tyto stays a single offline binary by default; these
// adapters light up only where the operator has the real tool present.
package adapter

import (
	"context"
	"os/exec"

	"github.com/dukotah/tyto/internal/state"
)

// DefaultMaxOutput caps captured tool output (combined stdout+stderr) to bound
// memory against a runaway tool. Adapters can override per call.
const DefaultMaxOutput = 1 << 20 // 1 MiB

// Detect returns the first candidate binary found on PATH, or "" if none are
// installed. Adapters pass their preferred names in order (e.g. "nxc","netexec").
func Detect(candidates ...string) string {
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// capWriter accumulates up to max bytes but keeps accepting writes (so the child
// process never blocks on a full pipe and is allowed to finish/drain).
type capWriter struct {
	buf []byte
	max int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		w.buf = append(w.buf, p[:room]...)
	}
	return len(p), nil
}

// Run executes name with args, bounded by ctx, returning combined stdout+stderr
// captured up to maxBytes (0 => DefaultMaxOutput). A non-zero exit is returned
// as err, but the captured output is ALSO returned — many security tools exit
// non-zero yet still print useful results, so callers should parse output
// regardless of err. No shell is involved: args are passed verbatim.
func Run(ctx context.Context, name string, args []string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxOutput
	}
	cw := &capWriter{max: maxBytes}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = cw
	cmd.Stderr = cw
	err := cmd.Run()
	return string(cw.buf), err
}

// Missing builds the standard graceful-degrade finding for when the external
// binary isn't installed. install is a short hint, e.g. "apt install nmap".
func Missing(toolName, target, install string) state.Finding {
	desc := toolName + " is not installed — optional shell-out adapter"
	if install != "" {
		desc += " (install: " + install + ")"
	}
	return state.Finding{
		Title:       toolName + " not available",
		Severity:    state.SeverityInfo,
		Target:      target,
		Description: desc,
		Tool:        toolName,
		Validated:   false,
	}
}

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
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/state"
)

// DefaultMaxOutput caps captured tool output (combined stdout+stderr) to bound
// memory against a runaway tool. Adapters can override per call.
const DefaultMaxOutput = 1 << 20 // 1 MiB

// execPrefix, when non-empty, wraps EVERY shelled-out command so it runs in a
// different environment than the host process — e.g. a WSL Kali distro when
// tyto.exe runs on Windows but should drive the real Kali toolbox. Empty means
// "run on the host" (the default, and what happens when the tyto binary itself
// runs inside Kali). Set once at startup via Configure before any run begins, so
// no locking is needed for the concurrent reads during a run.
var execPrefix []string

// Configure selects the execution backend from a spec string. It is the single
// switch that makes the whole tool fleet (and the operator shell) operate Kali:
//
//	""              run commands on the host (default / when tyto runs in Kali)
//	"wsl:<distro>"  run each command via `wsl -d <distro> -- ...`
//
// Returns an error for an unrecognized spec so a typo fails loudly at boot
// rather than silently running on the wrong box.
func Configure(spec string) error {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "":
		execPrefix = nil
		return nil
	case strings.HasPrefix(spec, "wsl:"):
		distro := strings.TrimSpace(strings.TrimPrefix(spec, "wsl:"))
		if distro == "" {
			return fmt.Errorf("exec backend %q: empty WSL distro name", spec)
		}
		execPrefix = []string{"wsl", "-d", distro, "--"}
		return nil
	default:
		return fmt.Errorf("unknown exec backend %q (want \"\" or \"wsl:<distro>\")", spec)
	}
}

// Backend returns a human-readable description of the active backend (for the
// startup banner), or "" when commands run on the host.
func Backend() string {
	if len(execPrefix) == 0 {
		return ""
	}
	return strings.Join(execPrefix[:len(execPrefix)-1], " ") // drop the trailing "--"
}

// wrap rewrites a logical (name, args) into the actual command to exec, applying
// the configured backend prefix. With no backend it is the identity.
func wrap(name string, args []string) (string, []string) {
	if len(execPrefix) == 0 {
		return name, args
	}
	full := make([]string, 0, len(execPrefix)-1+1+len(args))
	full = append(full, execPrefix[1:]...) // "-d","<distro>","--"
	full = append(full, name)
	full = append(full, args...)
	return execPrefix[0], full // "wsl"
}

// Detect returns the first candidate binary available in the execution
// environment, or "" if none are installed. On the host this is a PATH lookup;
// under a WSL backend it asks the distro (`command -v`) so detection reflects
// the box commands actually run on — not the Windows host's PATH.
func Detect(candidates ...string) string {
	for _, c := range candidates {
		if available(c) {
			return c
		}
	}
	return ""
}

// available reports whether binary c can be run by the active backend.
func available(c string) bool {
	if len(execPrefix) == 0 {
		_, err := exec.LookPath(c)
		return err == nil
	}
	// Probe inside the backend; bound it so a slow/cold WSL can't hang startup.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	name, args := wrap("command", []string{"-v", c})
	if err := exec.CommandContext(ctx, name, args...).Run(); err == nil {
		return true
	}
	// `command` is a shell builtin; some `wsl -- command` paths don't resolve it.
	// Fall back to a login shell so PATH/aliases are loaded like a real terminal.
	name, args = wrap("bash", []string{"-lc", "command -v " + c})
	return exec.CommandContext(ctx, name, args...).Run() == nil
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
	rn, ra := wrap(name, args)
	cmd := exec.CommandContext(ctx, rn, ra...)
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

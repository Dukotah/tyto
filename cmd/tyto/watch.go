package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/engine"
)

// newWatchCmd streams a running console's live event feed to the terminal, so an
// operator can SEE what the agent is doing in real time — every tool launch,
// scope decision, finding, and the run-complete marker — without a browser. It
// connects to `tyto serve`'s /api/events SSE endpoint and reconnects on its own,
// so you can leave `tyto watch` running across multiple runs.
func newWatchCmd() *cobra.Command {
	var addr string
	var noColor bool
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Live terminal feed of what the running console is doing (tools, decisions, findings)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			c := newColors(!noColor)
			url := "http://" + addr + "/api/events"
			fmt.Fprintf(out, "%styto watch%s  live feed from http://%s   (Ctrl-C to quit)\n", c.bold, c.reset, addr)
			fmt.Fprintf(out, "%swaiting for activity — start a scan in the console or chat…%s\n", c.dim, c.reset)
			starts := map[string]time.Time{}
			for {
				if err := streamEvents(url, out, c, starts); err != nil {
					fmt.Fprintf(out, "%s  (console at %s unreachable: %v — retrying)%s\n", c.dim, addr, err, c.reset)
				}
				time.Sleep(2 * time.Second)
			}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8090", "address of the running tyto console")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	return cmd
}

// streamEvents reads one SSE connection to completion (it ends when the console
// stops or the connection drops); the caller reconnects.
func streamEvents(url string, out io.Writer, c colors, starts map[string]time.Time) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20) // tool output lines can be large
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var ev engine.Event
		if json.Unmarshal([]byte(strings.TrimSpace(line[len("data:"):])), &ev) != nil {
			continue
		}
		printEvent(out, c, ev, starts)
	}
	return sc.Err()
}

func printEvent(out io.Writer, c colors, ev engine.Event, starts map[string]time.Time) {
	ts := c.dim + stamp(ev.Time) + c.reset
	key := ev.Tool + "|" + ev.Target
	switch ev.Kind {
	case "cycle":
		msg := ""
		if ev.Message != "" {
			msg = "  " + ev.Message
		}
		fmt.Fprintf(out, "\n%s  %s=== cycle %d ===%s%s\n", ts, c.cyan, ev.Cycle, msg, c.reset)
	case "action":
		if ev.Tool != "" && ev.Tool != "operator" {
			starts[key] = ev.Time
		}
		why := ""
		if ev.Message != "" {
			why = c.dim + "  " + trunc(ev.Message, 56) + c.reset
		}
		fmt.Fprintf(out, "%s    %sRUN %s %-13s %s%s\n", ts, c.bold, c.reset, ev.Tool, trunc(ev.Target, 46), why)
	case "decision":
		if strings.EqualFold(ev.Verdict, "deny") {
			fmt.Fprintf(out, "%s    %sDENY%s %-13s %s\n", ts, c.red, c.reset, ev.Tool, ev.Reason)
		} else if strings.EqualFold(ev.Verdict, "require_approval") {
			fmt.Fprintf(out, "%s    %sHOLD%s %-13s %s\n", ts, c.yellow, c.reset, ev.Tool, ev.Reason)
		}
	case "result":
		dur := ""
		if t0, ok := starts[key]; ok && !ev.Time.IsZero() && !t0.IsZero() {
			dur = fmt.Sprintf("%s (%.1fs)%s", c.dim, ev.Time.Sub(t0).Seconds(), c.reset)
		}
		fmt.Fprintf(out, "%s    %sdone%s %-13s %s%s\n", ts, c.green, c.reset, ev.Tool, trunc(ev.Message, 58), dur)
	case "finding":
		col := sevColor(c, ev.Severity)
		fmt.Fprintf(out, "%s    %sFIND%s %s[%s]%s %s\n", ts, c.bold, c.reset, col, strings.ToUpper(ev.Severity), c.reset, trunc(ev.Title, 66))
	case "approval_required":
		fmt.Fprintf(out, "%s    %sAPPROVE?%s %s on %s — needs operator approval (use the console)\n", ts, c.yellow, c.reset, ev.Tool, ev.Target)
	case "error":
		fmt.Fprintf(out, "%s    %sERROR%s %s\n", ts, c.red, c.reset, ev.Message)
	case "done":
		fmt.Fprintf(out, "\n%s  %s** RUN COMPLETE **%s %s%s\n\n", ts, c.green, c.reset, c.dim, ev.Message+c.reset)
	case "log":
		if m := strings.TrimSpace(ev.Message); m != "" {
			fmt.Fprintf(out, "%s    %s%s%s\n", ts, c.dim, trunc(m, 70), c.reset)
		}
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "        "
	}
	return t.Local().Format("15:04:05")
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// colors holds ANSI escapes (all ASCII, safe on any terminal); empty when disabled.
type colors struct{ reset, bold, dim, red, green, yellow, cyan, orange, blue string }

func newColors(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{
		reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
		red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
		cyan: "\x1b[36m", orange: "\x1b[38;5;208m", blue: "\x1b[34m",
	}
}

func sevColor(c colors, sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return c.red + c.bold
	case "high":
		return c.orange
	case "medium":
		return c.yellow
	case "low":
		return c.green
	case "info":
		return c.blue
	}
	return c.dim
}

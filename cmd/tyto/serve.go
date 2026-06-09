package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/methodology"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/store"
	"github.com/dukotah/tyto/pkg/version"
)

type toolRow struct{ Name, Category, Risk string }

type dashData struct {
	Version    string
	Engagement *engagement.Engagement // may be nil
	Report     *report.Report         // nil unless a state snapshot was found
	Tools      []toolRow
	Techniques []methodology.Technique
}

func newServeCmd() *cobra.Command {
	var engPath, statePath, addr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve a local web dashboard (capabilities + engagement results)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data := dashData{Version: version.Version, Techniques: methodology.All()}
			for _, t := range defaultRegistry().All() {
				data.Tools = append(data.Tools, toolRow{t.Name(), t.Category().String(), t.MaxRisk().String()})
			}
			sort.Slice(data.Tools, func(i, j int) bool {
				if data.Tools[i].Category != data.Tools[j].Category {
					return data.Tools[i].Category < data.Tools[j].Category
				}
				return data.Tools[i].Name < data.Tools[j].Name
			})

			if engPath != "" {
				eng, err := engagement.Load(engPath)
				if err != nil {
					return err
				}
				data.Engagement = eng
				sp := statePath
				if sp == "" {
					sp = eng.ID + ".state.json"
				}
				if snap, err := store.Load(sp); err == nil {
					st := state.New()
					snap.Into(st)
					rep := report.Build(eng, st)
					data.Report = &rep
				}
			}

			tmpl := template.Must(template.New("dash").Funcs(dashFuncs).Parse(dashHTML))
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_ = tmpl.Execute(w, data)
			})
			fmt.Fprintf(cmd.OutOrStdout(), "tyto dashboard live → http://%s   (Ctrl-C to stop)\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}
	cmd.Flags().StringVar(&engPath, "engagement", "", "engagement file to show results for (loads its state snapshot if present)")
	cmd.Flags().StringVar(&statePath, "state", "", "state snapshot path (default: <engagement-id>.state.json)")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8088", "listen address")
	return cmd
}

var dashFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"sevColor": func(s string) string {
		switch s {
		case "critical":
			return "#b10dc9"
		case "high":
			return "#ff4136"
		case "medium":
			return "#ff851b"
		case "low":
			return "#ffd400"
		default:
			return "#7fdbff"
		}
	},
}

const dashHTML = `<!doctype html><html><head><meta charset="utf-8">
<title>tyto dashboard</title>
<style>
 :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff}
 *{box-sizing:border-box} body{margin:0;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg)}
 header{padding:20px 28px;border-bottom:1px solid var(--border);display:flex;align-items:baseline;gap:14px}
 header h1{margin:0;font-size:22px;color:#fff} header .ver{color:var(--muted)}
 header .tag{margin-left:auto;color:var(--muted);font-size:12px}
 .wrap{max-width:1100px;margin:0 auto;padding:24px 28px}
 .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px 20px;margin-bottom:22px}
 .panel h2{margin:0 0 14px;font-size:15px;color:#fff;letter-spacing:.3px}
 .cards{display:flex;gap:14px;flex-wrap:wrap}
 .card{flex:1;min-width:120px;background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:14px}
 .card .n{font-size:26px;color:#fff} .card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse} th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
 th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
 .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#000}
 .muted{color:var(--muted)} .mono{font-family:inherit} code{color:var(--accent)}
 .grid2{display:grid;grid-template-columns:1fr 1fr;gap:22px} @media(max-width:760px){.grid2{grid-template-columns:1fr}}
 .ev{color:var(--muted);font-size:12px;word-break:break-all}
 .phase{color:var(--accent);font-weight:700}
</style></head><body>
<header>
 <h1>🦉 tyto</h1><span class="ver">{{.Version}}</span>
 <span class="tag">offline · scope-enforced · tamper-evident audit</span>
</header>
<div class="wrap">

{{if .Report}}
 <div class="panel">
  <h2>Engagement — {{.Report.EngagementID}} · {{.Report.Client}}</h2>
  <div class="cards">
   <div class="card"><div class="n">{{.Report.Totals.Assets}}</div><div class="l">Assets</div></div>
   <div class="card"><div class="n">{{.Report.Totals.Findings}}</div><div class="l">Findings</div></div>
   <div class="card"><div class="n">{{.Report.Totals.Validated}}</div><div class="l">Validated</div></div>
   {{range $sev, $n := .Report.Totals.BySeverity}}<div class="card"><div class="n" style="color:{{sevColor $sev}}">{{$n}}</div><div class="l">{{$sev}}</div></div>{{end}}
  </div>
  <p class="muted" style="margin:14px 0 0">Scope hash <code>{{.Report.ScopeHash}}</code></p>
 </div>

 <div class="panel">
  <h2>Findings</h2>
  <table><tr><th>Severity</th><th>CVSS</th><th>Finding</th><th>Target</th><th>Tool</th><th>Validated</th></tr>
  {{range .Report.Findings}}
   <tr>
    <td><span class="pill" style="background:{{sevColor .Severity}}">{{upper .Severity}}</span></td>
    <td>{{if gt .CVSS 0.0}}{{printf "%.1f" .CVSS}}{{else}}<span class="muted">—</span>{{end}}</td>
    <td>{{.Title}}{{if .Description}}<div class="ev">{{.Description}}</div>{{end}}{{if .Evidence}}<div class="ev">↳ {{.Evidence}}</div>{{end}}</td>
    <td class="ev">{{.Target}}</td>
    <td><code>{{.Tool}}</code></td>
    <td>{{if .Validated}}✓{{else}}<span class="muted">candidate</span>{{end}}</td>
   </tr>
  {{end}}
  </table>
 </div>
{{else}}
 <div class="panel"><h2>No engagement results loaded</h2>
  <p class="muted">Run an engagement (which saves a <code>&lt;id&gt;.state.json</code> snapshot), then start the dashboard with <code>tyto serve --engagement &lt;file&gt;</code> to see findings here. Below is what tyto can do.</p>
 </div>
{{end}}

 <div class="grid2">
  <div class="panel">
   <h2>Built-in tools ({{len .Tools}})</h2>
   <table><tr><th>Tool</th><th>Category</th><th>Max risk</th></tr>
   {{range .Tools}}<tr><td><code>{{.Name}}</code></td><td>{{.Category}}</td><td class="muted">{{.Risk}}</td></tr>{{end}}
   </table>
  </div>
  <div class="panel">
   <h2>Methodology ({{len .Techniques}} techniques)</h2>
   <table><tr><th>Phase</th><th>Technique</th><th>Tool</th></tr>
   {{range .Techniques}}<tr><td><span class="phase">{{.Phase}}</span></td><td>{{.Name}}</td><td>{{if .Tool}}<code>{{.Tool}}</code>{{else}}<span class="muted">—</span>{{end}}</td></tr>{{end}}
   </table>
  </div>
 </div>

 <p class="muted" style="text-align:center;margin-top:8px">Every action passes a deterministic Scope Guard the model can't bypass; every decision is written to a tamper-evident, hash-chained audit log.</p>
</div></body></html>`

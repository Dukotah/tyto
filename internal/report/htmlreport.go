package report

import (
	"bytes"
	"html/template"

	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/state"
)

// htmlReportData is the view model passed to the HTML template. It wraps the
// structured Report plus the fixed severity order used for the breakdown table.
type htmlReportData struct {
	Report
	SeverityOrder []string
}

// htmlTemplate renders a self-contained, print-friendly ("PDF-ready") client
// deliverable. All untrusted tool output (finding titles, descriptions,
// evidence, targets...) flows through html/template's contextual
// auto-escaping — never template.HTML — so an attacker-controlled finding
// cannot inject markup into the report.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": func(s string) string {
		// Avoid pulling strings into the template namespace for one helper.
		b := []byte(s)
		for i, c := range b {
			if c >= 'a' && c <= 'z' {
				b[i] = c - ('a' - 'A')
			}
		}
		return string(b)
	},
}).Parse(htmlTemplateText))

const htmlTemplateText = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Penetration Test Report — {{.EngagementID}}</title>
<style>
  :root {
    --crit: #7c1d1d; --high: #b23b16; --medium: #b8860b;
    --low: #2f6f4f; --info: #3a5a8c; --ink: #1a1a1a; --muted: #555;
    --rule: #d0d0d0; --bg-soft: #f6f6f4;
  }
  * { box-sizing: border-box; }
  body {
    font-family: "Helvetica Neue", Arial, sans-serif;
    color: var(--ink); line-height: 1.5; margin: 0;
    padding: 2.5rem; max-width: 60rem;
  }
  h1, h2, h3 { line-height: 1.2; }
  h1 { font-size: 1.9rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.3rem; margin: 2rem 0 .75rem; border-bottom: 2px solid var(--ink); padding-bottom: .25rem; }
  h3 { font-size: 1.05rem; margin: 0 0 .5rem; }
  .subtitle { color: var(--muted); margin: 0 0 1.5rem; }
  .meta { background: var(--bg-soft); border: 1px solid var(--rule); border-radius: 6px; padding: 1rem 1.25rem; }
  .meta dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1rem; margin: 0; }
  .meta dt { font-weight: 600; color: var(--muted); }
  .meta dd { margin: 0; word-break: break-word; }
  code, .mono { font-family: "SFMono-Regular", Consolas, monospace; font-size: .85em; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--rule); }
  th { background: var(--bg-soft); }
  .totals { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: .5rem 0 1rem; }
  .totals .stat { background: var(--bg-soft); border: 1px solid var(--rule); border-radius: 6px; padding: .6rem 1rem; min-width: 7rem; }
  .totals .num { font-size: 1.6rem; font-weight: 700; display: block; }
  .totals .lbl { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
  .finding { border: 1px solid var(--rule); border-left-width: 6px; border-radius: 6px; padding: 1rem 1.25rem; margin: 0 0 1rem; page-break-inside: avoid; }
  .finding.sev-critical { border-left-color: var(--crit); }
  .finding.sev-high { border-left-color: var(--high); }
  .finding.sev-medium { border-left-color: var(--medium); }
  .finding.sev-low { border-left-color: var(--low); }
  .finding.sev-info { border-left-color: var(--info); }
  .badge { display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .05em; padding: .15rem .5rem; border-radius: 3px; color: #fff; vertical-align: middle; }
  .badge.sev-critical { background: var(--crit); }
  .badge.sev-high { background: var(--high); }
  .badge.sev-medium { background: var(--medium); }
  .badge.sev-low { background: var(--low); }
  .badge.sev-info { background: var(--info); }
  .badge.validated { background: var(--low); }
  .badge.candidate { background: var(--muted); }
  .badge.cvss { background: var(--ink); }
  .finding .head { margin-bottom: .5rem; }
  .finding .head .title { font-weight: 700; font-size: 1.05rem; }
  .finding .attrs { color: var(--muted); font-size: .9rem; margin: .25rem 0 .5rem; }
  .finding .attrs span { margin-right: 1rem; }
  .finding .label { font-weight: 600; color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; margin: .6rem 0 .15rem; }
  .finding pre { background: var(--bg-soft); border: 1px solid var(--rule); border-radius: 4px; padding: .6rem .75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: .15rem 0 0; }
  .empty { color: var(--muted); font-style: italic; }
  footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--rule); color: var(--muted); font-size: .85rem; }

  @page { size: A4; margin: 18mm 16mm; }
  @media print {
    body { padding: 0; max-width: none; font-size: 11pt; }
    h2 { page-break-after: avoid; }
    .finding { page-break-inside: avoid; }
    .meta, .totals .stat, .finding pre, th { background: #fff !important; }
    .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    a[href]:after { content: ""; }
  }
</style>
</head>
<body>

<header>
  <h1>Penetration Test Report</h1>
  <p class="subtitle">Engagement {{.EngagementID}}</p>
  <div class="meta">
    <dl>
      <dt>Client</dt><dd>{{.Client}}</dd>
      <dt>Authorized by</dt><dd>{{.AuthorizedBy}}</dd>
      <dt>Agreement ref</dt><dd>{{.Agreement}}</dd>
      <dt>Scope hash</dt><dd class="mono">{{.ScopeHash}}</dd>
    </dl>
  </div>
</header>

<section>
  <h2>Executive summary</h2>
  <div class="totals">
    <div class="stat"><span class="num">{{.Totals.Assets}}</span><span class="lbl">Assets</span></div>
    <div class="stat"><span class="num">{{.Totals.Findings}}</span><span class="lbl">Findings</span></div>
    <div class="stat"><span class="num">{{.Totals.Validated}}</span><span class="lbl">Validated</span></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
      {{range .SeverityOrder}}
      <tr><td><span class="badge sev-{{.}}">{{upper .}}</span></td><td>{{index $.Totals.BySeverity .}}</td></tr>
      {{end}}
    </tbody>
  </table>
</section>

<section>
  <h2>Findings</h2>
  {{if .Findings}}
    {{range .Findings}}
    <article class="finding sev-{{.Severity}}">
      <div class="head">
        <span class="badge sev-{{.Severity}}">{{upper .Severity}}</span>
        {{if gt .CVSS 0.0}}<span class="badge cvss">CVSS {{printf "%.1f" .CVSS}}</span>{{end}}
        {{if .Validated}}<span class="badge validated">VALIDATED</span>{{else}}<span class="badge candidate">CANDIDATE</span>{{end}}
        <span class="title">{{.Title}}</span>
      </div>
      <div class="attrs">
        <span><strong>Target:</strong> <span class="mono">{{.Target}}</span></span>
        <span><strong>Tool:</strong> <span class="mono">{{.Tool}}</span></span>
        {{if .CVSSVector}}<span><strong>Vector:</strong> <span class="mono">{{.CVSSVector}}</span></span>{{end}}
      </div>
      {{if .Description}}<div class="label">Description</div><div>{{.Description}}</div>{{end}}
      {{if .Evidence}}<div class="label">Evidence</div><pre>{{.Evidence}}</pre>{{end}}
    </article>
    {{end}}
  {{else}}
    <p class="empty">No findings recorded.</p>
  {{end}}
</section>

<footer>
  Every decision and action in this engagement is recorded in a tamper-evident,
  hash-chained audit log. Verify its hash chain to confirm this report reflects
  exactly what ran.
</footer>

</body>
</html>
`

// RenderHTML produces a self-contained, print-friendly HTML report for the
// engagement — a client-ready "PDF-ready" deliverable. It embeds all CSS and
// references no external assets, so a browser's Print-to-PDF yields a clean A4
// document. (A native PDF engine is a later swap.)
//
// All finding text is untrusted tool output and is HTML-escaped by
// html/template's contextual auto-escaping.
func RenderHTML(eng *engagement.Engagement, st *state.State) ([]byte, error) {
	r := Build(eng, st)
	data := htmlReportData{
		Report:        r,
		SeverityOrder: []string{"critical", "high", "medium", "low", "info"},
	}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

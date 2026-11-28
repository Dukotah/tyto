package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/bench"
	"github.com/dukotah/tyto/internal/bench/lab"
	"github.com/dukotah/tyto/internal/planner/llm"
)

// newBenchCmd groups the benchmark commands: a deliberately vulnerable lab with
// a known answer key, and a scorer for runs against it.
func newBenchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Measure tyto (or the model driving it) against a vulnerable lab with a known answer key",
		Long: "bench answers \"did that change make tyto better?\" with numbers.\n\n" +
			"  lab      serve the deliberately vulnerable benchmark app on loopback\n" +
			"  run      start the lab, run tyto against it, and score the result in one step\n" +
			"  score    score a finished run (its JSON report + audit log) against the answer key\n" +
			"  compare  show what changed between two scored results\n\n" +
			"The lab plants real vulnerabilities in three tiers (surface, injection, chain) next to\n" +
			"decoys — safe endpoints that look vulnerable — so both missed bugs and false positives count.",
	}
	cmd.AddCommand(newBenchLabCmd(), newBenchRunCmd(), newBenchScoreCmd(), newBenchCompareCmd())
	return cmd
}

// labEngagementYAML is the engagement that authorizes a run against the lab at
// baseURL: scope is that one loopback URL, self-attested (it is your own
// process), with the exploit and identity tiers enabled so the whole arsenal is
// measurable.
func labEngagementYAML(baseURL string) string {
	return `# Engagement for the tyto benchmark lab. Scope is one loopback URL.
id: BENCH-LAB
client: tyto benchmark lab
description: Benchmark run against the built-in deliberately vulnerable lab.
authorization:
  authorized_by: operator (local benchmark lab)
  agreement_ref: tyto-bench-lab (own process, loopback only)
  mode: self-attested
scope:
  in_scope:
    - type: url
      value: ` + baseURL + `/
rules_of_engagement:
  max_risk: high
  allowed_categories: [recon, scan, exploit, identity]
  max_concurrent_actions: 4
`
}

// loopbackListener binds addr, refusing anything that is not a loopback address:
// the lab is vulnerable by design and must never be reachable from a network.
func loopbackListener(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("--addr: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("--addr %q is not a loopback address: the lab is deliberately vulnerable and only binds 127.0.0.1 / ::1", addr)
	}
	return net.Listen("tcp", addr)
}

func newBenchLabCmd() *cobra.Command {
	var addr, engOut string
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Serve the vulnerable benchmark app on loopback (for model- or agent-driven runs)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ln, err := loopbackListener(addr)
			if err != nil {
				return err
			}
			base := "http://" + ln.Addr().String()
			out := cmd.OutOrStdout()
			if engOut != "" {
				if err := os.WriteFile(engOut, []byte(labEngagementYAML(base)), 0o600); err != nil {
					return fmt.Errorf("write engagement: %w", err)
				}
				fmt.Fprintf(out, "engagement written to %s\n", engOut)
			}
			fmt.Fprintf(out, "tyto benchmark lab (answer key v%d) listening on %s — Ctrl-C to stop\n", lab.Version, base)
			fmt.Fprintf(out, "%d planted vulnerabilities, %d decoys. DELIBERATELY VULNERABLE: loopback only.\n", len(lab.Answers()), len(lab.Decoys()))
			srv := &http.Server{Handler: lab.Handler()}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			go func() { <-ctx.Done(); _ = srv.Close() }()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "loopback address to listen on")
	cmd.Flags().StringVar(&engOut, "engagement-out", "", "also write a ready-to-use engagement file for this lab address")
	return cmd
}

// oracleClient builds the planner backend for the "oracle" reference run: the
// lab's perfectly-aimed plan, rendered as canned planner turns. Category and
// risk are filled from the registry (they are advisory; the guard uses the
// tool's own authoritative values regardless).
func oracleClient(base string) (llm.Client, int, error) {
	reg := defaultRegistry()
	var turns []string
	for _, cycle := range lab.OraclePlan() {
		var acts []map[string]any
		for _, st := range cycle {
			t, ok := reg.Get(st.Tool)
			if !ok {
				return nil, 0, fmt.Errorf("oracle plan names unknown tool %q", st.Tool)
			}
			params := map[string]string{}
			for k, v := range st.Params {
				if k == "login_url" {
					v = base + v
				}
				params[k] = v
			}
			acts = append(acts, map[string]any{
				"tool": st.Tool, "category": t.Category().String(), "target": base + st.Path,
				"risk": t.MaxRisk().String(), "params": params, "rationale": "benchmark oracle plan",
			})
		}
		raw, err := json.Marshal(map[string]any{"actions": acts})
		if err != nil {
			return nil, 0, err
		}
		turns = append(turns, string(raw))
	}
	return &llm.Mock{Responses: turns}, len(turns), nil
}

func newBenchRunCmd() *cobra.Command {
	var plannerKind, model, ollamaURL, llmBaseURL, label, out, keep string
	var cycles, maxTokens int
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the lab, run tyto against it, and score the result",
		Long: "run is the one-step benchmark. It starts the lab on a free loopback port, runs a\n" +
			"full engagement against it with the chosen planner, and scores the outcome.\n\n" +
			"Planners:\n" +
			"  oracle    every relevant tool aimed at exactly the right URL — the TOOL CEILING.\n" +
			"            What it misses is a tool gap; no planner can do better with today's tools.\n" +
			"  scripted  the fixed no-model demo script — the FLOOR.\n" +
			"  ollama    a local model plans (use --model).\n" +
			"  openai    any OpenAI-compatible endpoint plans (use --model, --llm-base-url).\n\n" +
			"A model's score between floor and ceiling is how much of the tools' potential its\n" +
			"planning realizes. To benchmark an external agent over MCP, use `bench lab` + `tyto mcp`\n" +
			"+ `bench score` instead (see docs/BENCHMARK.md).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ln, err := loopbackListener("127.0.0.1:0")
			if err != nil {
				return err
			}
			srv := &http.Server{Handler: lab.Handler()}
			go func() { _ = srv.Serve(ln) }()
			defer srv.Close()
			base := "http://" + ln.Addr().String()

			dir := keep
			if dir == "" {
				if dir, err = os.MkdirTemp("", "tyto-bench-"); err != nil {
					return err
				}
				defer os.RemoveAll(dir)
			} else if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			engPath := filepath.Join(dir, "lab-engagement.yaml")
			if err := os.WriteFile(engPath, []byte(labEngagementYAML(base)), 0o600); err != nil {
				return err
			}
			reportPath, auditPath := filepath.Join(dir, "report.json"), filepath.Join(dir, "audit.jsonl")
			// Each bench run is independent: never append to a previous run's trail.
			_ = os.Remove(auditPath)

			o := &runOptions{
				engPath: engPath, plannerKind: plannerKind, model: model, ollamaURL: ollamaURL, llmBaseURL: llmBaseURL,
				cycles: cycles, maxTokens: maxTokens, auditPath: auditPath, reportFormat: "json", reportOut: reportPath,
				statePath: filepath.Join(dir, "state.json"),
			}
			if plannerKind == "oracle" {
				client, n, err := oracleClient(base)
				if err != nil {
					return err
				}
				o.client, o.cycles = client, n
			}
			if label == "" {
				label = plannerKind
				if model != "" {
					label += ":" + model
				}
			}

			errOut := cmd.ErrOrStderr()
			fmt.Fprintf(errOut, "benchmark lab on %s — running planner %q\n", base, label)
			// The engine's progress log goes to stderr so stdout carries only the scorecard.
			runCmd := &cobra.Command{}
			runCmd.SetOut(errOut)
			runCmd.SetContext(cmd.Context())
			if err := o.run(runCmd, nil); err != nil {
				return fmt.Errorf("engagement run: %w", err)
			}
			return scoreAndEmit(cmd, label, reportPath, auditPath, out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&plannerKind, "planner", "oracle", "who plans: oracle|scripted|ollama|openai")
	f.StringVar(&model, "model", "", "model name for --planner ollama|openai")
	f.StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "ollama base URL")
	f.StringVar(&llmBaseURL, "llm-base-url", "", "OpenAI-compatible API base URL (key from TYTO_LLM_API_KEY or OPENAI_API_KEY)")
	f.IntVar(&cycles, "cycles", 12, "max plan/act cycles for model planners (ignored for oracle)")
	f.IntVar(&maxTokens, "max-tokens", 0, "approximate planner token budget; 0 = unlimited")
	f.StringVar(&label, "label", "", "name for this result (default: the planner, plus the model)")
	f.StringVar(&out, "out", "", "write the scored result as JSON to this file (input to `bench compare`)")
	f.StringVar(&keep, "keep", "", "keep the run's engagement, report and audit log in this directory")
	return cmd
}

// scoreAndEmit scores a report (+ optional audit log), prints the Markdown
// scorecard to stdout, and writes the JSON result to out when set.
func scoreAndEmit(cmd *cobra.Command, label, reportPath, auditPath, out string) error {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	findings, err := bench.ParseReport(data)
	if err != nil {
		return err
	}
	var entries []audit.Entry
	if auditPath != "" {
		if entries, err = audit.ReadFile(auditPath); err != nil {
			return err
		}
		if err := audit.Verify(entries); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %v\n", err)
		}
	}
	res := bench.Score(label, findings, entries)
	fmt.Fprintln(cmd.OutOrStdout(), bench.RenderMarkdown(res))
	if out != "" {
		raw, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "result written to %s\n", out)
	}
	return nil
}

func newBenchScoreCmd() *cobra.Command {
	var reportPath, auditPath, label, out string
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Score a finished run against the lab answer key",
		Long: "score grades a run you drove yourself (for example an external agent over `tyto mcp`).\n" +
			"It needs the run's JSON report; give it the audit log too for effort metrics.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reportPath == "" {
				return fmt.Errorf("--report is required (a tyto JSON report: --report-format json)")
			}
			if label == "" {
				label = strings.TrimSuffix(filepath.Base(reportPath), filepath.Ext(reportPath))
			}
			return scoreAndEmit(cmd, label, reportPath, auditPath, out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&reportPath, "report", "", "the run's JSON report (required)")
	f.StringVar(&auditPath, "audit", "", "the run's audit log, for effort metrics (optional)")
	f.StringVar(&label, "label", "", "name for this result (default: the report file name)")
	f.StringVar(&out, "out", "", "write the scored result as JSON to this file")
	return cmd
}

func newBenchCompareCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <baseline.json> <new.json>",
		Short: "Show what changed between two scored results",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var rs [2]bench.Result
			for i, p := range args {
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				if err := json.Unmarshal(data, &rs[i]); err != nil {
					return fmt.Errorf("%s is not a bench result: %w", p, err)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), bench.Compare(rs[0], rs[1]))
			return nil
		},
	}
}

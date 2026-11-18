package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/blue/attack"
	"github.com/dukotah/tyto/internal/blue/coverage"
	"github.com/dukotah/tyto/internal/blue/detect"
	"github.com/dukotah/tyto/internal/blue/event"
	"github.com/dukotah/tyto/internal/blue/ingest"
	"github.com/dukotah/tyto/internal/blue/triage"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/purple"
)

// newBlueCmd builds the `tyto blue` subtree: the defensive mirror of the engine.
// ingest -> detect -> triage, plus the ATT&CK coverage grid and the purple loop.
func newBlueCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blue",
		Short: "Blue-team detection, triage & purple loop (tyto blue)",
		Long: "tyto blue — the defensive mirror of tyto. Ingest security logs, detect\n" +
			"with Sigma rules (ATT&CK-tagged), triage alerts with a local model, score\n" +
			"detection coverage, and run the purple loop (attack -> prove detection ->\n" +
			"draft the missing rule).",
	}
	cmd.AddCommand(newBlueDetectCmd(), newBlueTriageCmd(), newBlueCoverageCmd(), newBluePurpleCmd())
	return cmd
}

// openInput returns the file at path, or stdin when path is "" or "-".
func openInput(path string) (io.ReadCloser, error) {
	if path == "" || path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

// --- tyto blue detect ---

func newBlueDetectCmd() *cobra.Command {
	var sensor, file string
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Parse logs and run Sigma detection",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := openInput(file)
			if err != nil {
				return err
			}
			defer r.Close()
			events, perr := ingest.Parse(sensor, r)
			if perr != nil && len(events) == 0 {
				return fmt.Errorf("ingest: %w", perr)
			}
			det, err := detect.NewDetector()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ingested %d events; %d detection rules loaded\n\n", len(events), det.RuleCount())
			n := 0
			for _, ev := range events {
				for _, d := range det.Eval(ev) {
					if !d.Matched {
						continue
					}
					n++
					fmt.Fprintf(out, "[%s] %s  (%s)  target=%s rule=%s\n",
						strings.ToUpper(d.Severity.String()), d.RuleTitle, d.Technique, detTarget(d.Event), d.RuleID)
				}
			}
			fmt.Fprintf(out, "\n%d detections\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&sensor, "sensor", "jsonl", "log source: suricata | wazuh | jsonl")
	cmd.Flags().StringVar(&file, "file", "-", "input log file (default stdin)")
	return cmd
}

// --- tyto blue triage ---

func newBlueTriageCmd() *cobra.Command {
	var sensor, file, model, ollamaURL string
	var dry bool
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Detect, then triage each alert with a local model (real vs noise)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := openInput(file)
			if err != nil {
				return err
			}
			defer r.Close()
			events, perr := ingest.Parse(sensor, r)
			if perr != nil && len(events) == 0 {
				return fmt.Errorf("ingest: %w", perr)
			}
			det, err := detect.NewDetector()
			if err != nil {
				return err
			}
			var client llm.Client
			if !dry {
				client = llm.NewOllama(ollamaURL, model)
			} // nil client -> triage uses its deterministic no-LLM fallback
			brain := triage.New(client)

			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			n := 0
			for _, ev := range events {
				for _, d := range det.Eval(ev) {
					if !d.Matched {
						continue
					}
					n++
					a := triage.Alert{
						ID:           d.RuleID,
						Title:        d.RuleTitle,
						Severity:     d.Severity.String(),
						Technique:    d.Technique,
						EventMeta:    d.Event.SafeMeta(),
						EventContent: d.Event.Content(),
						Count:        1,
					}
					v, err := brain.Triage(ctx, a)
					if err != nil {
						return err
					}
					src := "fallback"
					if v.UsedModel {
						src = "model"
					}
					fmt.Fprintf(out, "%-12s conf=%.2f [%s]  %s (%s)\n    %s\n",
						strings.ToUpper(v.Disposition.String()), v.Confidence, src, d.RuleTitle, d.Technique, v.Rationale)
				}
			}
			if n == 0 {
				fmt.Fprintln(out, "no detections to triage")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sensor, "sensor", "jsonl", "log source: suricata | wazuh | jsonl")
	cmd.Flags().StringVar(&file, "file", "-", "input log file (default stdin)")
	cmd.Flags().StringVar(&model, "model", defaultBlueModel(), "local model for triage (Ollama)")
	cmd.Flags().StringVar(&ollamaURL, "ollama-url", "http://localhost:11434", "Ollama base URL")
	cmd.Flags().BoolVar(&dry, "dry", false, "skip the model; use the deterministic fallback only")
	return cmd
}

// --- tyto blue coverage ---

func newBlueCoverageCmd() *cobra.Command {
	var showGaps bool
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show ATT&CK detection coverage (loaded rules vs catalog)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			det, err := detect.NewDetector()
			if err != nil {
				return err
			}
			cat := attack.Embedded()
			m := coverage.Build(cat, loadedRuleTechniques(det), nil)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ATT&CK coverage — %d rules over a %d-technique catalog\n", det.RuleCount(), cat.Len())
			fmt.Fprintf(out, "covered: %d/%d (%.1f%%)\n\n", m.Summary.Covered, m.Summary.Total, m.Summary.CoveredPct)
			fmt.Fprintln(out, "by tactic:")
			for _, tac := range m.Tactics() {
				s := m.ByTactic[tac]
				if s.Covered == 0 {
					continue
				}
				fmt.Fprintf(out, "  %-24s %d/%d\n", tac, s.Covered, s.Total)
			}
			if showGaps {
				gaps := m.Gaps()
				fmt.Fprintf(out, "\n%d uncovered techniques (gaps)\n", len(gaps))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showGaps, "gaps", false, "also summarize uncovered techniques")
	return cmd
}

// --- tyto blue purple ---

// purpleScenario is the on-disk purple-run definition: attack steps with the
// technique each exercises and the telemetry events it produced. This is the
// file-driven stand-in for a live tyto attack + sensor.
type purpleScenario struct {
	Steps []struct {
		Technique string        `json:"technique"`
		Name      string        `json:"name"`
		Events    []event.Event `json:"events"`
	} `json:"steps"`
}

type scenarioAttacker struct{ steps []purple.Step }

func (s scenarioAttacker) Run(context.Context) ([]purple.Step, error) { return s.steps, nil }

func newBluePurpleCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "purple",
		Short: "Run the purple loop from a scenario: attack -> prove detection -> draft missing rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return fmt.Errorf("--scenario is required")
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var sc purpleScenario
			if err := json.Unmarshal(raw, &sc); err != nil {
				return fmt.Errorf("parse scenario: %w", err)
			}
			steps := make([]purple.Step, 0, len(sc.Steps))
			for _, s := range sc.Steps {
				steps = append(steps, purple.Step{Technique: s.Technique, Name: s.Name, Events: s.Events})
			}
			det, err := detect.NewDetector()
			if err != nil {
				return err
			}
			rep, err := purple.New(det, attack.Embedded()).Run(cmd.Context(), scenarioAttacker{steps: steps})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "purple loop — %d events, %d techniques attacked\n", rep.Events, len(rep.Attacked))
			fmt.Fprintf(out, "  detected: %s\n", strings.Join(orNone(rep.Detected), ", "))
			fmt.Fprintf(out, "  MISSED:   %s\n", strings.Join(orNone(rep.Missed), ", "))
			fmt.Fprintf(out, "  coverage: %d/%d techniques (%.1f%%)\n\n",
				rep.Matrix.Summary.Covered, rep.Matrix.Summary.Total, rep.Matrix.Summary.CoveredPct)
			for _, d := range rep.Drafts {
				fmt.Fprintf(out, "----- drafted rule for %s -----\n%s\n", d.Technique, d.YAML)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "scenario", "", "JSON scenario file (steps: technique + events)")
	return cmd
}

// --- helpers ---

func detTarget(e event.Event) string {
	if e.DstIP != "" {
		return e.DstIP
	}
	if e.Host != "" {
		return e.Host
	}
	return e.SrcIP
}

func loadedRuleTechniques(det *detect.Detector) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range det.Rules() {
		id := strings.ToUpper(strings.TrimSpace(r.Technique))
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func defaultBlueModel() string {
	if m := os.Getenv("TYTO_MODEL"); m != "" {
		return m
	}
	return "qwen3:8b"
}

func orNone(xs []string) []string {
	if len(xs) == 0 {
		return []string{"(none)"}
	}
	return xs
}

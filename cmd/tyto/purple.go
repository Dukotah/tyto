package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/purple"
)

// newPurpleCmd groups the blue-team / purple-team commands. All of them are
// offline post-processing over an audit log: they never contact a target, need
// no engagement file and no model.
func newPurpleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "purple",
		Short: "Blue-team deliverables from an audit log: attack timeline, detection coverage, ATT&CK layer",
		Long: "purple turns a tyto audit log into defender-facing output.\n\n" +
			"  timeline  what tyto did, when, to what, mapped to ATT&CK, and where a SOC should look\n" +
			"  score     correlate the defender's alert export against the timeline: what was detected, what was missed\n" +
			"  layer     an ATT&CK Navigator layer of the techniques exercised (or of detection coverage)\n\n" +
			"These commands only read files. Nothing is sent to any target.",
	}
	cmd.AddCommand(newPurpleTimelineCmd(), newPurpleScoreCmd(), newPurpleLayerCmd())
	return cmd
}

// purpleCommon holds the flags every purple subcommand shares.
type purpleCommon struct {
	auditPath string
	source    string
	resolve   bool
	out       string
}

func (p *purpleCommon) bind(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&p.auditPath, "audit", "", "path to the tyto audit log (.audit.jsonl) (required)")
	f.StringVar(&p.source, "source", "", "address the test traffic came from, as the client saw it (recorded in the output for the SOC)")
	f.BoolVar(&p.resolve, "resolve", false, "resolve target hostnames to IPs now, so alerts keyed by IP match activity keyed by name (does DNS lookups)")
	f.StringVar(&p.out, "out", "", "write output to this file (default: stdout)")
}

func (p *purpleCommon) timeline(errOut io.Writer) (purple.Timeline, error) {
	if p.auditPath == "" {
		return purple.Timeline{}, fmt.Errorf("--audit is required")
	}
	entries, err := audit.ReadFile(p.auditPath)
	if err != nil {
		return purple.Timeline{}, err
	}
	opts := purple.BuildOptions{Source: p.source}
	if p.resolve {
		opts.Resolve = purple.NetResolver
	}
	tl := purple.Build(entries, opts)
	if !tl.ChainVerified {
		fmt.Fprintf(errOut, "WARNING: audit hash chain is broken — %s\n", tl.ChainError)
	}
	return tl, nil
}

func (p *purpleCommon) write(cmd *cobra.Command, data []byte) error {
	if p.out == "" {
		_, err := cmd.OutOrStdout().Write(append(data, '\n'))
		return err
	}
	// 0600: the output names client targets and the techniques used against them.
	if err := os.WriteFile(p.out, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", p.out, err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "written to %s\n", p.out)
	return nil
}

func newPurpleTimelineCmd() *cobra.Command {
	p := &purpleCommon{}
	var format string
	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Export the attack timeline for the SOC (what ran, when, against what, mapped to ATT&CK)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tl, err := p.timeline(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "md", "markdown":
				data = []byte(purple.RenderTimelineMarkdown(tl))
			case "json":
				if data, err = json.MarshalIndent(tl, "", "  "); err != nil {
					return err
				}
			case "csv":
				if data, err = purple.RenderTimelineCSV(tl); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (want md|json|csv)", format)
			}
			return p.write(cmd, data)
		},
	}
	p.bind(cmd)
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|json|csv")
	return cmd
}

// alertFlags are the alert-loading and correlation flags shared by score/layer.
type alertFlags struct {
	alertsPath string
	tz         string
	grace      time.Duration
	skew       time.Duration
}

func (a *alertFlags) bind(cmd *cobra.Command, required bool) {
	f := cmd.Flags()
	req := ""
	if required {
		req = " (required)"
	}
	f.StringVar(&a.alertsPath, "alerts", "", "defender alert export: JSON array, NDJSON, or CSV with a header row"+req)
	f.StringVar(&a.tz, "alert-tz", "UTC", "IANA time zone assumed for alert timestamps that carry no zone (e.g. America/Chicago)")
	f.DurationVar(&a.grace, "grace", 10*time.Minute, "how long after an action ends an alert may still be credited to it")
	f.DurationVar(&a.skew, "skew", 2*time.Minute, "tolerated clock difference between the tyto host and the defender's tooling")
}

func (a *alertFlags) score(tl purple.Timeline, errOut io.Writer) (purple.Scorecard, error) {
	loc, err := time.LoadLocation(a.tz)
	if err != nil {
		return purple.Scorecard{}, fmt.Errorf("--alert-tz: %w", err)
	}
	f, err := os.Open(a.alertsPath)
	if err != nil {
		return purple.Scorecard{}, fmt.Errorf("open alerts: %w", err)
	}
	defer f.Close()
	alerts, skipped, err := purple.ParseAlerts(f, loc)
	if err != nil {
		return purple.Scorecard{}, err
	}
	if len(skipped) > 0 {
		fmt.Fprintf(errOut, "WARNING: %d alert record(s) had no readable timestamp and were skipped (first: record %d)\n", len(skipped), skipped[0])
	}
	return purple.Score(tl, alerts, purple.ScoreOptions{Grace: a.grace, Skew: a.skew}), nil
}

func newPurpleScoreCmd() *cobra.Command {
	p, a := &purpleCommon{}, &alertFlags{}
	var format, layerOut string
	var minCoverage float64
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Score detection coverage: correlate the defender's alerts against what tyto did",
		Long: "score loads the SOC's alert export for the engagement window and correlates it with\n" +
			"the attack timeline. It reports which actions were detected, which were missed, time\n" +
			"to detect, coverage per ATT&CK technique and per target, and any alerts that fired\n" +
			"during the test but match nothing tyto did.\n\n" +
			"Alert fields are recognized by common names (ECS, Splunk CIM, Sentinel, plain CSV):\n" +
			"a timestamp is required; destination host/IP, source IP, rule name and ATT&CK\n" +
			"technique id are used when present.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.alertsPath == "" {
				return fmt.Errorf("--alerts is required")
			}
			tl, err := p.timeline(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			sc, err := a.score(tl, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "md", "markdown":
				data = []byte(purple.RenderScoreMarkdown(sc))
			case "json":
				if data, err = json.MarshalIndent(sc, "", "  "); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (want md|json)", format)
			}
			if err := p.write(cmd, data); err != nil {
				return err
			}
			if layerOut != "" {
				layer, err := purple.RenderNavigatorLayer(tl, &sc)
				if err != nil {
					return err
				}
				if err := os.WriteFile(layerOut, layer, 0o600); err != nil {
					return fmt.Errorf("write %s: %w", layerOut, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "ATT&CK Navigator layer written to %s\n", layerOut)
			}
			if minCoverage > 0 && sc.CoveragePct < minCoverage {
				return fmt.Errorf("detection coverage %.0f%% is below the required %.0f%%", sc.CoveragePct, minCoverage)
			}
			return nil
		},
	}
	p.bind(cmd)
	a.bind(cmd, true)
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|json")
	cmd.Flags().StringVar(&layerOut, "layer-out", "", "also write an ATT&CK Navigator layer colored by detection coverage to this file")
	cmd.Flags().Float64Var(&minCoverage, "min-coverage", 0, "exit non-zero if detection coverage is below this percentage (for scheduled detection-regression runs)")
	return cmd
}

func newPurpleLayerCmd() *cobra.Command {
	p, a := &purpleCommon{}, &alertFlags{}
	cmd := &cobra.Command{
		Use:   "layer",
		Short: "Export an ATT&CK Navigator layer (techniques exercised, or detection coverage with --alerts)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tl, err := p.timeline(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var sc *purple.Scorecard
			if a.alertsPath != "" {
				s, err := a.score(tl, cmd.ErrOrStderr())
				if err != nil {
					return err
				}
				sc = &s
			}
			data, err := purple.RenderNavigatorLayer(tl, sc)
			if err != nil {
				return err
			}
			return p.write(cmd, data)
		},
	}
	p.bind(cmd)
	a.bind(cmd, false)
	return cmd
}

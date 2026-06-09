// Command tyto is the CLI entrypoint for the AI-orchestrated authorized
// penetration-testing platform.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/dukotah/tyto/internal/audit"
	"github.com/dukotah/tyto/internal/engagement"
	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/guard"
	"github.com/dukotah/tyto/internal/planner"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/report"
	"github.com/dukotah/tyto/internal/state"
	"github.com/dukotah/tyto/internal/tool"
	"github.com/dukotah/tyto/internal/tool/builtin/portscan"
	"github.com/dukotah/tyto/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("tyto %s\n", version.Version)
	case "tools":
		cmdTools()
	case "engagement":
		cmdEngagement(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`tyto — AI-orchestrated authorized penetration testing

USAGE:
  tyto <command> [flags]

COMMANDS:
  run           Run an engagement (plan -> guard -> execute loop)
  engagement    Work with engagement files (validate)
  tools         List registered tool adapters
  version       Print version
  help          Show this help

EXAMPLES:
  tyto engagement validate configs/engagement.example.yaml
  tyto run --engagement configs/engagement.example.yaml --dry-run
  tyto tools

Run "tyto <command> -h" for command flags.
`)
}

// defaultRegistry wires the built-in tool adapters.
func defaultRegistry() *tool.Registry {
	r := tool.NewRegistry()
	r.MustRegister(portscan.New())
	return r
}

func cmdTools() {
	r := defaultRegistry()
	fmt.Println("Registered tools:")
	for _, t := range r.All() {
		fmt.Printf("  %-14s category=%-8s max_risk=%s\n", t.Name(), t.Category(), t.MaxRisk())
	}
}

func cmdEngagement(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tyto engagement validate <file>")
		os.Exit(2)
	}
	switch args[0] {
	case "validate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: tyto engagement validate <file>")
			os.Exit(2)
		}
		eng, err := engagement.Load(args[1])
		if err != nil {
			fatal(err.Error())
		}
		fmt.Printf("OK: %s for %s — %d objective(s), %d in-scope, %d out-of-scope, max_risk=%s\n",
			eng.ID, eng.Client, len(eng.Objectives),
			len(eng.Scope.InScope), len(eng.Scope.OutOfScope), eng.RoE.MaxRisk)
	default:
		fmt.Fprintf(os.Stderr, "unknown engagement subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	engPath := fs.String("engagement", "", "path to engagement YAML (required)")
	dryRun := fs.Bool("dry-run", false, "plan and guard only; never execute tools")
	plannerKind := fs.String("planner", "", "planner backend: ollama|mock (default: ollama, or mock with --dry-run)")
	model := fs.String("model", "llama3.1", "ollama model name")
	ollamaURL := fs.String("ollama-url", "http://localhost:11434", "ollama base URL")
	cycles := fs.Int("cycles", 1, "max plan/act cycles")
	auditPath := fs.String("audit", "", "audit log path (default: <engagement-id>.audit.jsonl)")
	noReport := fs.Bool("no-report", false, "skip printing the report at the end")
	_ = fs.Parse(args)

	if *engPath == "" {
		fatal("--engagement is required")
	}

	eng, err := engagement.Load(*engPath)
	if err != nil {
		fatal(err.Error())
	}

	kind := *plannerKind
	if kind == "" {
		if *dryRun {
			kind = "mock"
		} else {
			kind = "ollama"
		}
	}
	var client llm.Client
	switch kind {
	case "mock":
		client = llm.NewDemoMock()
	case "ollama":
		client = llm.NewOllama(*ollamaURL, *model)
	default:
		fatal(fmt.Sprintf("unknown planner backend %q (want ollama|mock)", kind))
	}

	ap := *auditPath
	if ap == "" {
		ap = eng.ID + ".audit.jsonl"
	}
	alog, closeAudit, err := audit.Open(ap)
	if err != nil {
		fatal(fmt.Sprintf("open audit log: %v", err))
	}
	defer func() { _ = closeAudit() }()

	st := state.New()
	eg := engine.New(
		eng,
		guard.New(eng),
		planner.New(client),
		defaultRegistry(),
		st,
		alog,
		os.Stdout,
		engine.Options{DryRun: *dryRun, MaxCycles: *cycles},
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("tyto %s — engagement %s (%s)\n", version.Version, eng.ID, eng.Client)
	fmt.Printf("planner=%s  dry-run=%v  audit=%s\n", client.Name(), *dryRun, ap)

	if err := eg.Run(ctx); err != nil {
		fatal(err.Error())
	}

	if !*noReport {
		fmt.Println()
		fmt.Println(report.Render(eng, st))
	}
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	os.Exit(1)
}

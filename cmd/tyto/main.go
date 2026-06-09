// Command tyto is the CLI entrypoint for the AI-orchestrated authorized
// penetration-testing platform.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

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
	case "authorize":
		cmdAuthorize(os.Args[2:])
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
  authorize     Client-side: generate a keypair / sign an engagement (keygen|sign)
  tools         List registered tool adapters
  version       Print version
  help          Show this help

EXAMPLES:
  tyto engagement validate configs/engagement.example.yaml
  tyto run --engagement configs/engagement.example.yaml --dry-run
  tyto authorize keygen
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

// toolSnapshot builds the immutable, read-only authority the Scope Guard gates
// on: each tool's authoritative category + risk ceiling, with no access to
// Execute. The guard never trusts model-supplied risk/category.
func toolSnapshot(r *tool.Registry) map[string]guard.ToolMeta {
	m := make(map[string]guard.ToolMeta)
	for _, t := range r.All() {
		m[t.Name()] = guard.ToolMeta{Category: t.Category(), MaxRisk: t.MaxRisk()}
	}
	return m
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

// cmdAuthorize is the client-side helper for producing authorization material.
// Signing happens on the CLIENT's machine with the CLIENT's private key; tyto
// only ever VERIFIES at run time. This subcommand is a convenience so a client
// without their own tooling can still generate a keypair and sign an engagement.
//
//	tyto authorize keygen
//	tyto authorize sign --engagement <file> --private-key <b64> --max-tier high [--targets <t1,t2>]
func cmdAuthorize(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tyto authorize <keygen|sign> [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println("# Give the client_public_key to the tyto operator (pin it in the engagement).")
		fmt.Println("# Keep the private_key SECRET on the client's machine; use it with 'authorize sign'.")
		fmt.Printf("client_public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("private_key:       %s\n", base64.StdEncoding.EncodeToString(priv))
	case "sign":
		fs := flag.NewFlagSet("authorize sign", flag.ExitOnError)
		engPath := fs.String("engagement", "", "engagement YAML to authorize (required)")
		privB64 := fs.String("private-key", "", "client base64 Ed25519 private key (required)")
		maxTier := fs.String("max-tier", "high", "highest authorized risk tier: passive|low|medium|high")
		targets := fs.String("targets", "", "comma-separated targets the grant covers (default: all in-scope)")
		_ = fs.Parse(args[1:])
		if *engPath == "" || *privB64 == "" {
			fatal("--engagement and --private-key are required")
		}
		eng, err := engagement.Load(*engPath)
		if err != nil {
			fatal(err.Error())
		}
		priv, err := base64.StdEncoding.DecodeString(*privB64)
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			fatal("--private-key is not a valid base64 Ed25519 private key")
		}
		privKey := ed25519.PrivateKey(priv)
		sig := ed25519.Sign(privKey, eng.CanonicalBytes())
		pub := privKey.Public().(ed25519.PublicKey)
		fmt.Println("# Add this under authorization.grants in the engagement YAML:")
		fmt.Printf("  - public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
		fmt.Printf("    signature: %s\n", base64.StdEncoding.EncodeToString(sig))
		fmt.Printf("    max_tier: %s\n", *maxTier)
		if *targets == "" {
			fmt.Println("    covers_targets:   # mirror the in-scope targets the client authorizes")
		} else {
			fmt.Println("    covers_targets:")
			for _, t := range splitCSV(*targets) {
				fmt.Printf("      - {type: domain, value: %s}   # adjust type as needed\n", t)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown authorize subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	engPath := fs.String("engagement", "", "path to engagement YAML (required)")
	dryRun := fs.Bool("dry-run", false, "plan and guard only; never execute tools")
	plannerKind := fs.String("planner", "", "planner backend: ollama|mock (default: ollama, or mock with --dry-run)")
	model := fs.String("model", "qwen3:14b", "ollama model name")
	ollamaURL := fs.String("ollama-url", "http://localhost:11434", "ollama base URL")
	cycles := fs.Int("cycles", 3, "max plan/act cycles (loop halts early on no progress)")
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

	// Verify any client authorization grants up front and fail closed on a bad one
	// (a forged/tampered grant must abort, not silently fall back to no-auth).
	grants, err := eng.VerifiedGrants()
	if err != nil {
		fatal(fmt.Sprintf("authorization: %v", err))
	}

	st := state.New()
	reg := defaultRegistry()

	// Bind the signed scope hash + verified-grant count into the audit chain so any
	// post-hoc scope widening is detectable against the trail.
	if err := alog.Record("authorization", map[string]any{
		"scope_hash": eng.ScopeHash(), "verified_grants": len(grants),
		"client_key": eng.Authorization.ClientPublicKeyB64,
	}); err != nil {
		fatal(fmt.Sprintf("write audit head: %v", err))
	}

	eg := engine.New(
		eng,
		guard.New(eng, toolSnapshot(reg), grants),
		planner.New(client),
		reg,
		st,
		alog,
		os.Stdout,
		engine.Options{DryRun: *dryRun, MaxCycles: *cycles},
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Hard-stop the run when the permitted operating window closes (in addition to
	// SIGINT). No windows configured ⇒ no time-based deadline.
	if deadline, ok := eng.RoE.Deadline(time.Now().UTC()); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
		fmt.Printf("operating window closes at %s — run will stop then\n", deadline.Format("15:04 MST"))
	}

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

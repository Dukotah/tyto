package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dukotah/tyto/internal/engine"
	"github.com/dukotah/tyto/internal/planner/llm"
	"github.com/dukotah/tyto/internal/tool/builtin/shell"
)

// Operator mode is tyto's autonomous-operator loop: the local model is given a
// task and works it on the Kali box ONE shell command at a time — it runs a
// command, READS the output, and decides the next command itself, the way a
// human operator iterates in a terminal. This is the "agent loose in the box"
// capability, kept honest by the same two-tier shell gate:
//
//   - read-only toolbox commands run unattended (that's the point — fluid work);
//   - mutating/arbitrary commands run ONLY when the operator has flipped free-run
//     ON (an explicit "I'm here and accountable" switch); otherwise they are
//     blocked and fed back as an observation so the model routes around them.
//
// Target traffic against client assets still belongs in `run` mode, where the
// Scope Guard gates scope/risk/authorization. This loop is for working the box.
const (
	operatorMaxSteps = 14
	operatorObsCap   = 2400 // per-step observation chars fed back to the model
)

// operatorStepSchema is the JSON the model emits each turn.
var operatorStepSchema = json.RawMessage(`{"type":"object","properties":{` +
	`"thought":{"type":"string"},` +
	`"action":{"type":"string","enum":["shell","done"]},` +
	`"command":{"type":"string"},` +
	`"summary":{"type":"string"}},"required":["action"]}`)

// startOperator launches the autonomous loop in the background and streams each
// step to the live event feed. It returns immediately so the chat reply can say
// "on it". Only one operator loop runs at a time.
func (c *console) startOperator(task string) string {
	task = strings.TrimSpace(task)
	if task == "" {
		return "no task given"
	}
	c.mu.Lock()
	if c.operatorCancel != nil {
		c.mu.Unlock()
		return "I'm already working on something — say 'stop' first"
	}
	client := c.newChatClient()
	ctx, cancel := context.WithCancel(context.Background())
	c.operatorCancel = cancel
	c.mu.Unlock()
	go c.runOperator(ctx, task, client)
	return ""
}

// runOperator is the loop body. It is model-driven but every command passes the
// deterministic shell gate before it can run.
func (c *console) runOperator(ctx context.Context, task string, client llm.SchemaClient) {
	defer func() {
		c.mu.Lock()
		c.operatorCancel = nil
		c.mu.Unlock()
	}()

	c.opEvent("log", "🧠 operator: "+task)
	system := c.operatorSystem()

	var transcript strings.Builder
	fmt.Fprintf(&transcript, "TASK: %s\n\n", task)

	for step := 1; step <= operatorMaxSteps; step++ {
		select {
		case <-ctx.Done():
			c.opEvent("log", "operator: stopped.")
			return
		default:
		}

		raw, err := client.GenerateSchema(ctx, system, transcript.String(), operatorStepSchema)
		if err != nil {
			c.opEvent("error", "operator model error: "+err.Error())
			return
		}
		var d struct {
			Thought string `json:"thought"`
			Action  string `json:"action"`
			Command string `json:"command"`
			Summary string `json:"summary"`
		}
		_ = json.Unmarshal([]byte(raw), &d)

		if d.Action == "done" {
			s := strings.TrimSpace(d.Summary)
			if s == "" {
				s = strings.TrimSpace(d.Thought)
			}
			if s == "" {
				s = "Done."
			}
			c.opEvent("log", "✅ operator: "+s)
			return
		}

		cmd := strings.TrimSpace(d.Command)
		if cmd == "" {
			fmt.Fprintf(&transcript, "Step %d: (no command) — provide a shell command or finish with action=done.\n", step)
			continue
		}
		if t := strings.TrimSpace(d.Thought); t != "" {
			c.opEvent("log", "💭 "+t)
		}
		c.opEvent("log", "$ "+cmd)

		// Deterministic two-tier gate — identical source of truth as the chat path.
		if !shell.IsReadOnly(cmd) && !c.freeRun() {
			obs := "BLOCKED: that command can change the box, and free-run mode is OFF. " +
				"Use a read-only approach, or tell the operator to enable free-run."
			c.opEvent("log", "⛔ "+obs)
			fmt.Fprintf(&transcript, "Step %d ($ %s):\n%s\n\n", step, cmd, obs)
			continue
		}

		out, ok := c.runShell(ctx, cmd)
		obs := out
		if len(obs) > operatorObsCap {
			obs = obs[:operatorObsCap] + "\n… (truncated)"
		}
		status := "ok"
		if !ok {
			status = "non-zero exit"
		}
		c.opEvent("result", trimForFeed(out))
		fmt.Fprintf(&transcript, "Step %d ($ %s) [%s]:\n%s\n\n", step, cmd, status, obs)
	}
	c.opEvent("log", "operator: reached the step limit ("+fmt.Sprint(operatorMaxSteps)+") — say more or give a narrower task.")
}

// operatorSystem builds the system prompt, including the safe engagement context.
func (c *console) operatorSystem() string {
	c.mu.Lock()
	eng, st, free := c.eng, c.st, c.operatorFreeRun
	c.mu.Unlock()
	mode := "READ-ONLY (only non-mutating toolbox commands will run; anything else is blocked)"
	if free {
		mode = "FREE-RUN (the operator is present and has authorized arbitrary local commands)"
	}
	return "You are tyto's autonomous operator, working inside a Kali Linux box for an AUTHORIZED " +
		"penetration test. You work like a human at a terminal: issue ONE shell command, READ its " +
		"output, then decide the next command. Reply ONLY as JSON matching the schema " +
		"{thought, action:'shell'|'done', command, summary}.\n" +
		"- action='shell': put a single command in 'command' and a short 'thought' on why.\n" +
		"- action='done': you've completed the task — put the answer/result in 'summary'.\n" +
		"These commands run on the OPERATOR'S OWN Kali box (the toolbox): inspect wordlists, " +
		"installed tools, configs, and process loot you already have. Do NOT send traffic to client " +
		"targets from here — authorized target scanning/exploitation goes through the engagement run, " +
		"where the Scope Guard gates it.\n" +
		"Current gate: " + mode + ". Prefer read-only commands; they always run. If a command is " +
		"blocked, adapt. Stop with action='done' as soon as the task is answered — don't pad steps.\n\n" +
		chatContext(eng, st)
}

// opEvent streams one operator step to the live feed (and the run history).
func (c *console) opEvent(kind, msg string) {
	c.broadcast(engine.Event{Kind: kind, Message: msg, Tool: "operator", Time: time.Now().UTC()})
}

// freeRun reports whether the operator has authorized arbitrary local commands.
func (c *console) freeRun() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.operatorFreeRun
}

func trimForFeed(s string) string {
	const cap = 600
	s = strings.TrimRight(s, "\n")
	if len(s) > cap {
		s = s[:cap] + " …"
	}
	return s
}

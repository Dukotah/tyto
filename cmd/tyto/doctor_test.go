package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dukotah/tyto/internal/planner/llm"
)

// findCheck returns the named check from the evaluated report, across all sections.
func findCheck(secs []section, name string) (check, bool) {
	for _, s := range secs {
		for _, c := range s.checks {
			if c.name == name {
				return c, true
			}
		}
	}
	return check{}, false
}

func TestEvaluate_CoreAlwaysOK(t *testing.T) {
	secs := evaluate(doctorEnv{version: "tyto test", pulledModels: map[string]bool{}, arsenal: map[string]string{}})
	for _, name := range []string{"tyto binary", "detection templates"} {
		c, ok := findCheck(secs, name)
		if !ok {
			t.Fatalf("missing core check %q", name)
		}
		if c.status != statusOK {
			t.Errorf("core check %q = %v, want statusOK", name, c.status)
		}
	}
}

func TestEvaluate_OllamaMissingIsFixable(t *testing.T) {
	secs := evaluate(doctorEnv{
		ollamaBin:    "",
		ollamaURL:    "http://localhost:11434",
		pulledModels: map[string]bool{},
		arsenal:      map[string]string{},
		recommended:  llm.ModelChoice{Model: "qwen3:14b", Reason: "16GB tier"},
	})
	c, ok := findCheck(secs, "ollama")
	if !ok || c.status != statusMissing {
		t.Fatalf("ollama check = %+v, ok=%v; want statusMissing", c, ok)
	}
	if c.fix == "" {
		t.Error("a missing dependency must carry a fix")
	}
}

func TestEvaluate_RecommendedModelPulled(t *testing.T) {
	secs := evaluate(doctorEnv{
		ollamaBin:    "/usr/bin/ollama",
		ollamaUp:     true,
		ollamaURL:    "http://localhost:11434",
		pulledModels: map[string]bool{"qwen3:14b": true},
		recommended:  llm.ModelChoice{Model: "qwen3:14b", Reason: "16GB tier"},
		arsenal:      map[string]string{},
	})
	c, ok := findCheck(secs, "recommended model")
	if !ok || c.status != statusOK {
		t.Fatalf("recommended model = %+v, ok=%v; want statusOK", c, ok)
	}
}

func TestEvaluate_OtherModelPresentIsWarnNotMissing(t *testing.T) {
	secs := evaluate(doctorEnv{
		ollamaUp:     true,
		ollamaURL:    "http://localhost:11434",
		pulledModels: map[string]bool{"llama3:8b": true},
		recommended:  llm.ModelChoice{Model: "qwen3:14b", Reason: "16GB tier"},
		arsenal:      map[string]string{},
	})
	c, _ := findCheck(secs, "recommended model")
	if c.status != statusWarn {
		t.Errorf("with another model present, recommended model = %v, want statusWarn", c.status)
	}
}

func TestModelPulled_TolerantMatch(t *testing.T) {
	cases := []struct {
		pulled map[string]bool
		want   string
		ok     bool
	}{
		{map[string]bool{"qwen3:14b": true}, "qwen3:14b", true},
		{map[string]bool{"qwen3:14b:latest": false, "qwen3:latest": true}, "qwen3:14b", true},
		{map[string]bool{"qwen3": true}, "qwen3:14b", true},
		{map[string]bool{"llama3:8b": true}, "qwen3:14b", false},
		{map[string]bool{}, "qwen3:8b", false},
	}
	for _, tc := range cases {
		if got := modelPulled(tc.pulled, tc.want); got != tc.ok {
			t.Errorf("modelPulled(%v, %q) = %v, want %v", tc.pulled, tc.want, got, tc.ok)
		}
	}
}

func TestEvaluate_ArsenalFoundVsMissing(t *testing.T) {
	secs := evaluate(doctorEnv{
		pulledModels: map[string]bool{},
		arsenal:      map[string]string{"nmap": "/usr/bin/nmap"},
		recommended:  llm.ModelChoice{Model: "qwen3:8b"},
	})
	if c, _ := findCheck(secs, "nmap"); c.status != statusOK {
		t.Errorf("present tool nmap = %v, want statusOK", c.status)
	}
	// An absent optional tool is INFO, never a hard failure — tyto runs without it.
	if c, _ := findCheck(secs, "nuclei"); c.status != statusInfo {
		t.Errorf("absent optional tool nuclei = %v, want statusInfo", c.status)
	}
}

func TestRenderDoctor_IncludesNextSteps(t *testing.T) {
	var buf bytes.Buffer
	renderDoctor(&buf, evaluate(doctorEnv{pulledModels: map[string]bool{}, arsenal: map[string]string{}}))
	out := buf.String()
	for _, want := range []string{"tyto doctor", "--dry-run", "What you can do right now"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n---\n%s", want, out)
		}
	}
}

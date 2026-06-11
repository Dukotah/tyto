package main

import "testing"

// TestShellNotPlannerSelectable locks in a security invariant: the `shell` tool
// runs arbitrary commands on tyto's OWN host (not the engagement target), so it
// must never appear in the registry the autonomous planner selects from. If it
// did, a hallucinated or prompt-injected plan could achieve host RCE while the
// guard only validated the in-scope target. The operator console runs shell
// commands directly (gated by IsReadOnly + explicit confirmation), never via the
// planner — so nothing legitimately needs shell in this registry.
func TestShellNotPlannerSelectable(t *testing.T) {
	for _, n := range defaultRegistry().Names() {
		if n == "shell" {
			t.Fatal("`shell` is in defaultRegistry() — it executes arbitrary host commands and MUST NOT be planner-selectable; the operator paths construct it directly")
		}
	}
}

package planner

import (
	"encoding/json"
	"testing"

	"github.com/dukotah/tyto/internal/action"
)

func TestActionSchemaEnumMatchesTaxonomy(t *testing.T) {
	var schema struct {
		Properties struct {
			Actions struct {
				Items struct {
					Required   []string `json:"required"`
					Properties struct {
						Category struct {
							Enum []string `json:"enum"`
						} `json:"category"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"actions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(ActionSchema(), &schema); err != nil {
		t.Fatal(err)
	}
	got := schema.Properties.Actions.Items.Properties.Category.Enum
	if len(got) != len(action.AllCategories()) {
		t.Fatalf("schema category enum has %d values, taxonomy has %d", len(got), len(action.AllCategories()))
	}
	for i, c := range action.AllCategories() {
		if got[i] != c.String() {
			t.Errorf("enum[%d] = %q, want %q", i, got[i], c.String())
		}
	}
	// tool/category/target/risk must be required.
	req := map[string]bool{}
	for _, r := range schema.Properties.Actions.Items.Required {
		req[r] = true
	}
	for _, want := range []string{"tool", "category", "target", "risk"} {
		if !req[want] {
			t.Errorf("schema does not require %q", want)
		}
	}
}

func TestDecodeActionsValidatesCategoryFailClosed(t *testing.T) {
	// Unknown category must be rejected, NOT silently defaulted.
	_, err := decodeActions(`{"actions":[{"tool":"portscan","category":"banana","target":"h","risk":"low"}]}`)
	if err == nil {
		t.Fatal("unknown category must fail validation")
	}
	// A valid category parses.
	got, err := decodeActions(`{"actions":[{"tool":"portscan","category":"scan","target":"h","risk":"medium"}]}`)
	if err != nil || len(got) != 1 {
		t.Fatalf("valid action should decode, got %v / %v", got, err)
	}
	// Category alias is tolerated.
	if _, err := decodeActions(`{"actions":[{"tool":"x","category":"reconnaissance","target":"h","risk":"low"}]}`); err != nil {
		t.Fatalf("category alias should be accepted: %v", err)
	}
}

func TestDecodeActionsUnknownRiskFailsSafe(t *testing.T) {
	// Unlike category, an unknown risk falls back to passive (guard is authority).
	got, err := decodeActions(`{"actions":[{"tool":"x","category":"scan","target":"h","risk":"wat"}]}`)
	if err != nil || len(got) != 1 || got[0].Risk != action.RiskPassive {
		t.Fatalf("unknown risk should fail safe to passive, got %v / %v", got, err)
	}
}

func TestDecodeActionsRejectsEmptyToolOrTarget(t *testing.T) {
	if _, err := decodeActions(`{"actions":[{"tool":"","category":"scan","target":"h","risk":"low"}]}`); err == nil {
		t.Fatal("empty tool must be rejected")
	}
	if _, err := decodeActions(`{"actions":[{"tool":"x","category":"scan","target":"","risk":"low"}]}`); err == nil {
		t.Fatal("empty target must be rejected")
	}
}

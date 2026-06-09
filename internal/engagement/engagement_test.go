package engagement

import "testing"

// TestURLScopeNoPrefixConfusion pins the fix for naive HasPrefix URL matching:
// matching must be host- and path-segment-aware, not a raw string prefix.
func TestURLScopeNoPrefixConfusion(t *testing.T) {
	s := Scope{InScope: []Target{{Type: TargetURL, Value: "https://app.example.com/app"}}}
	cases := []struct {
		target string
		want   bool
	}{
		{"https://app.example.com/app", true},
		{"https://app.example.com/app/admin", true},
		{"https://app.example.com/app-admin", false},    // different segment
		{"https://app.example.com.evil.com/app", false}, // different host (the classic bypass)
		{"https://other.example.com/app", false},
		{"https://app.example.com/other", false},
	}
	for _, tc := range cases {
		if got := s.Contains(tc.target); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

// TestRoECategoryValidation ensures an unknown category in the rules of
// engagement fails CLOSED at load rather than silently never-matching.
func TestRoECategoryValidation(t *testing.T) {
	good := RoE{MaxRisk: "medium", AllowedCategories: []string{"recon", "scan"}, ForbiddenCategories: []string{"exploit"}}
	if err := good.validate(); err != nil {
		t.Fatalf("valid categories should pass, got: %v", err)
	}
	bad := RoE{MaxRisk: "medium", AllowedCategories: []string{"recon", "definitely-not-a-category"}}
	if err := bad.validate(); err == nil {
		t.Fatal("unknown category should fail validation, got nil error")
	}
}

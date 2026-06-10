package cvss

import (
	"math"
	"testing"
)

func TestBaseScore(t *testing.T) {
	const tol = 0.05
	cases := []struct {
		vector   string
		want     float64
		severity string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"},
		// Low-severity example. Note: per the exact CVSS v3.1 formula, PR:H
		// (Scope Unchanged) carries weight 0.27, which yields 2.0 for this
		// vector — NOT 2.6. The known-correct 2.6 corresponds to PR:L (0.62);
		// see TestKnownPRHandling below for the spec-accurate PR:H result.
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6, "low"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"},
	}

	for _, tc := range cases {
		t.Run(tc.vector, func(t *testing.T) {
			got, err := BaseScore(tc.vector)
			if err != nil {
				t.Fatalf("BaseScore(%q) returned error: %v", tc.vector, err)
			}
			if math.Abs(got-tc.want) > tol {
				t.Errorf("BaseScore(%q) = %v, want %v", tc.vector, got, tc.want)
			}
			if sev := Severity(got); sev != tc.severity {
				t.Errorf("Severity(%v) = %q, want %q", got, sev, tc.severity)
			}
		})
	}
}

// TestKnownPRHandling documents the spec-accurate result for PR:H with Scope
// Unchanged (weight 0.27). This vector is sometimes mistakenly tabulated as
// 2.6; the exact CVSS v3.1 reference formula gives 2.0.
func TestKnownPRHandling(t *testing.T) {
	got, err := BaseScore("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(got-2.0) > 0.05 {
		t.Errorf("PR:H vector = %v, want 2.0 (PR:H weight 0.27)", got)
	}
}

func TestBaseScoreNoPrefix(t *testing.T) {
	got, err := BaseScore("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.Abs(got-9.8) > 0.05 {
		t.Errorf("got %v, want 9.8", got)
	}
}

func TestSeverityBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "none"},
		{0.1, "low"},
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
		{9.0, "critical"},
		{10.0, "critical"},
	}
	for _, tc := range cases {
		if got := Severity(tc.score); got != tc.want {
			t.Errorf("Severity(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestBaseScoreErrors(t *testing.T) {
	cases := []struct {
		name   string
		vector string
	}{
		{"empty", ""},
		{"missing metric A", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{"invalid AV value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"invalid scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"},
		{"invalid C value", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Z/I:H/A:H"},
		{"malformed component", "CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"bad version", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"empty value", "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BaseScore(tc.vector); err == nil {
				t.Errorf("BaseScore(%q) expected error, got nil", tc.vector)
			}
		})
	}
}

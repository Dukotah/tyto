package engagement

import (
	"fmt"
	"net"
	"strings"
)

// TargetType enumerates the kinds of scope entries.
type TargetType string

const (
	TargetCIDR   TargetType = "cidr"
	TargetIP     TargetType = "ip"
	TargetDomain TargetType = "domain"
	TargetURL    TargetType = "url"
)

// Target is a single in-scope or out-of-scope entry.
type Target struct {
	Type  TargetType `yaml:"type"`
	Value string     `yaml:"value"`
}

func (t Target) validate() error {
	if t.Value == "" {
		return fmt.Errorf("target value is empty")
	}
	switch t.Type {
	case TargetCIDR:
		if _, _, err := net.ParseCIDR(t.Value); err != nil {
			return fmt.Errorf("invalid cidr %q: %w", t.Value, err)
		}
	case TargetIP:
		if net.ParseIP(t.Value) == nil {
			return fmt.Errorf("invalid ip %q", t.Value)
		}
	case TargetDomain, TargetURL:
		// permissive — any non-empty string
	default:
		return fmt.Errorf("unknown target type %q", t.Type)
	}
	return nil
}

// matches reports whether the given target string falls under this entry.
func (t Target) matches(target string) bool {
	switch t.Type {
	case TargetURL:
		return strings.HasPrefix(target, t.Value)
	case TargetCIDR:
		_, ipnet, err := net.ParseCIDR(t.Value)
		if err != nil {
			return false
		}
		ip := net.ParseIP(hostOf(target))
		return ip != nil && ipnet.Contains(ip)
	case TargetIP:
		return hostOf(target) == t.Value
	case TargetDomain:
		h := hostOf(target)
		return h == t.Value || strings.HasSuffix(h, "."+t.Value)
	default:
		return false
	}
}

// Scope is the set of things you may and may not touch.
type Scope struct {
	InScope    []Target `yaml:"in_scope"`
	OutOfScope []Target `yaml:"out_of_scope"`
}

// Contains reports whether a target string is in scope. Out-of-scope always
// beats in-scope: if any out-of-scope entry matches, the answer is no.
func (s Scope) Contains(target string) bool {
	for _, t := range s.OutOfScope {
		if t.matches(target) {
			return false
		}
	}
	for _, t := range s.InScope {
		if t.matches(target) {
			return true
		}
	}
	return false
}

func (s Scope) validate() error {
	if len(s.InScope) == 0 {
		return fmt.Errorf("scope: at least one in_scope target is required")
	}
	for _, t := range s.InScope {
		if err := t.validate(); err != nil {
			return fmt.Errorf("scope.in_scope: %w", err)
		}
	}
	for _, t := range s.OutOfScope {
		if err := t.validate(); err != nil {
			return fmt.Errorf("scope.out_of_scope: %w", err)
		}
	}
	return nil
}

// hostOf extracts the bare host from a target that may be a URL or host:port.
func hostOf(target string) string {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return t
}

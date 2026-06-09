package action

import (
	"fmt"
	"strings"
)

// Category is the closed, deterministic taxonomy the Scope Guard enforces an
// engagement's allowed/forbidden lists against. It is tyto-native and ordered
// loosely along PTES phases. A Tool declares its *authoritative* Category; the
// model's self-declared category (action.Action.Category) is advisory only and
// never gates. ATT&CK tactic / kill-chain stage are carried as separate metadata
// on technique-catalog nodes, never folded into this vocabulary.
type Category int

const (
	CategoryRecon       Category = iota // intelligence gathering (passive + active recon)
	CategoryScan                        // enumeration, fingerprinting, vuln scanning
	CategoryExploit                     // exploitation attempts
	CategoryPostExploit                 // post-exploitation, persistence, looting
	CategoryIdentity                    // credential / identity ops (auth, AD, spraying)
	CategoryDoS                         // denial of service (almost always forbidden)
)

func (c Category) String() string {
	switch c {
	case CategoryRecon:
		return "recon"
	case CategoryScan:
		return "scan"
	case CategoryExploit:
		return "exploit"
	case CategoryPostExploit:
		return "post-exploit"
	case CategoryIdentity:
		return "identity"
	case CategoryDoS:
		return "dos"
	default:
		return "unknown"
	}
}

// ParseCategory parses a category name (case-insensitive, alias-tolerant).
// Unknown names are an error so callers can FAIL CLOSED rather than silently
// never-matching a forbidden-list entry.
func ParseCategory(s string) (Category, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "recon", "reconnaissance":
		return CategoryRecon, nil
	case "scan", "scanning":
		return CategoryScan, nil
	case "exploit", "exploitation":
		return CategoryExploit, nil
	case "post-exploit", "post_exploit", "postexploit", "post-exploitation":
		return CategoryPostExploit, nil
	case "identity", "credential", "credentials", "creds":
		return CategoryIdentity, nil
	case "dos", "denial-of-service":
		return CategoryDoS, nil
	default:
		return 0, fmt.Errorf("unknown action category %q", s)
	}
}

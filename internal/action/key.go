package action

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// CanonicalKey is a stable identity for an action: the same tool, normalized
// target, and params (regardless of map order) always produce the same key. The
// engine uses it to skip duplicate actions deterministically, so it must never
// depend on Go map iteration order.
//
// Key = SHA256( tool \x00 normalizedTarget \x00 {sorted "k=v\n"} ).
func (a Action) CanonicalKey() string {
	h := sha256.New()
	h.Write([]byte(a.Tool))
	h.Write([]byte{0})
	h.Write([]byte(normalizeTarget(a.Target)))
	h.Write([]byte{0})

	keys := make([]string, 0, len(a.Params))
	for k := range a.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		h.Write([]byte(a.Params[k]))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeTarget collapses targets that are equivalent for dedup purposes:
// case-folded, with trailing dots and slashes trimmed. It is intentionally
// coarse — over-collapsing two near-identical targets only ever skips a
// duplicate, which is the desired direction (fail toward fewer repeated probes).
func normalizeTarget(s string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "/.")
}

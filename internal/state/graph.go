package state

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The normalized asset graph
// --------------------------
// The flat asset list (state.go) records whatever a caller submits, keyed by the
// caller's own ID. The graph layer here is the NORMALIZED, deduplicated view of
// the same discoveries arranged as an explicit hierarchy:
//
//	root_domain -> subdomain -> ip -> service -> endpoint
//
// Agents and tools submit raw Observations; the PROGRAM (not the caller) computes
// the dedup key and the parent link, and auto-creates any missing ancestors so a
// lone endpoint still hangs off a real chain. Callers are never trusted to dedup.
//
// AddAsset mirrors each mappable flat asset into the graph (see state.go), so the
// hierarchy is populated by the existing discovery path with no caller change;
// Observe is the first-class entrypoint for code that wants to submit a typed
// observation directly.
//
// Quarantine: GraphNode.Value and Kind are planner-safe (sanitized on the way to
// any prompt, like every other safe field); the computed Key/ParentKey are
// identity-only and quarantined; Attrs is tool-controlled free text and never
// reaches Summary — exactly the boundary the flat Asset already enforces.

// AssetKind is a level in the normalized asset hierarchy.
type AssetKind string

const (
	KindRootDomain AssetKind = "root_domain"
	KindSubdomain  AssetKind = "subdomain"
	KindIP         AssetKind = "ip"
	KindService    AssetKind = "service"
	KindEndpoint   AssetKind = "endpoint"
)

// rank orders the kinds from the root of the hierarchy downward, for a
// deterministic Graph() ordering.
func (k AssetKind) rank() int {
	switch k {
	case KindRootDomain:
		return 0
	case KindSubdomain:
		return 1
	case KindIP:
		return 2
	case KindService:
		return 3
	case KindEndpoint:
		return 4
	default:
		return 5
	}
}

// Key returns the program-computed dedup key for a (kind, normalized value) pair.
// The NUL separator keeps kinds that share a value (e.g. a root_domain that is
// also observed as a subdomain) from colliding. Callers that already hold a
// normalized value (e.g. the report, cross-referencing a GraphNode) can use this
// to reconstruct a node's key.
func (k AssetKind) Key(value string) string { return string(k) + "\x00" + value }

// Observation is a raw, untrusted datum a tool or agent submits about the target.
// The program derives the dedup key and the parent link from it — callers supply
// neither. Attrs is tool-controlled free text and is quarantined like Asset.Attrs.
type Observation struct {
	Kind AssetKind
	// Value is the natural identifier for the kind:
	//  root_domain: "example.com"
	//  subdomain:   "api.example.com"
	//  ip:          "203.0.113.10"
	//  service:     "203.0.113.10:443" (host:port)
	//  endpoint:    "https://api.example.com/login"
	Value     string
	Attrs     map[string]string
	FirstSeen time.Time
}

// GraphNode is one deduplicated node in the normalized asset hierarchy. Key and
// ParentKey are program-computed identities (never rendered to the model); Kind
// and Value are planner-safe; Attrs is quarantined free text.
type GraphNode struct {
	Key       string            `planner:"quarantined"` // computed dedup key; identity only
	Kind      AssetKind         `planner:"safe"`         // hierarchy level
	Value     string            `planner:"safe"`         // normalized natural identifier
	ParentKey string            `planner:"quarantined"` // computed parent key ("" = graph root)
	Attrs     map[string]string // quarantined: not a string field; never enters Summary
	FirstSeen time.Time
}

// Observe records a raw observation into the normalized graph: the program
// normalizes the value, computes the dedup key and parent link, auto-creates any
// missing ancestor nodes, and merges Attrs into an existing node. It returns the
// resolved node and whether it was newly created. A value that cannot be
// normalized for its kind yields (nil, false).
func (s *State) Observe(obs Observation) (*GraphNode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.observeLocked(obs.Kind, obs.Value, obs.Attrs, obs.FirstSeen)
}

// observeLocked is the shared, already-locked ingest used by Observe and by
// AddAsset's mirror. It recurses up the parent chain to materialize ancestors.
func (s *State) observeLocked(kind AssetKind, value string, attrs map[string]string, firstSeen time.Time) (*GraphNode, bool) {
	value = normalizeFor(kind, value)
	if value == "" {
		return nil, false
	}
	if firstSeen.IsZero() {
		firstSeen = time.Now().UTC()
	}
	if s.graph == nil {
		s.graph = make(map[string]*GraphNode)
	}

	// Compute (and auto-create) the parent before linking, so the chain is always
	// complete regardless of discovery order.
	var parentKey string
	if pk, pv := parentOf(kind, value, attrs); pk != "" && pv != "" {
		if parent, _ := s.observeLocked(pk, pv, nil, firstSeen); parent != nil {
			parentKey = parent.Key
		}
	}

	key := kind.Key(value)
	n, existed := s.graph[key]
	if !existed {
		n = &GraphNode{Key: key, Kind: kind, Value: value, ParentKey: parentKey, FirstSeen: firstSeen}
		s.graph[key] = n
	} else {
		if parentKey != "" && n.ParentKey == "" {
			n.ParentKey = parentKey
		}
		if !firstSeen.IsZero() && (n.FirstSeen.IsZero() || firstSeen.Before(n.FirstSeen)) {
			n.FirstSeen = firstSeen
		}
	}
	// Program-owned attr merge: first writer wins per key, callers never dedup.
	for k, v := range attrs {
		if n.Attrs == nil {
			n.Attrs = make(map[string]string)
		}
		if _, ok := n.Attrs[k]; !ok {
			n.Attrs[k] = v
		}
	}
	return n, !existed
}

// AddGraphNode inserts a pre-computed node verbatim, WITHOUT recomputing its key
// or parent link. It exists for replaying a persisted graph (see sqlstore); the
// discovery path uses Observe/AddAsset instead. Returns true if the key was new.
func (s *State) AddGraphNode(n *GraphNode) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.graph == nil {
		s.graph = make(map[string]*GraphNode)
	}
	_, existed := s.graph[n.Key]
	s.graph[n.Key] = n
	return !existed
}

// Graph returns a snapshot of the normalized hierarchy, ordered by hierarchy
// level then value for a deterministic prompt/report.
func (s *State) Graph() []*GraphNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*GraphNode, 0, len(s.graph))
	for _, n := range s.graph {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := out[i].Kind.rank(), out[j].Kind.rank(); ri != rj {
			return ri < rj
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// mirrorAssetLocked folds a flat Asset into the graph on a best-effort basis. It
// is called by AddAsset while State.mu is already held. Asset types that do not
// map onto a hierarchy level (e.g. "cidr") are skipped — the asset still lives in
// the flat list, it just has no normalized node.
func (s *State) mirrorAssetLocked(a *Asset) {
	kind, ok := kindForAssetType(a.Type, a.Value)
	if !ok {
		return
	}
	s.observeLocked(kind, a.Value, a.Attrs, a.FirstSeen)
}

// kindForAssetType maps a flat Asset.Type onto a hierarchy level. "host"/"domain"
// are resolved to ip/root_domain/subdomain by inspecting the value, since the
// flat vocabulary does not distinguish them.
func kindForAssetType(typ, value string) (AssetKind, bool) {
	switch typ {
	case "service":
		return KindService, true
	case "url", "endpoint":
		return KindEndpoint, true
	case "ip":
		return KindIP, true
	case "root_domain":
		return KindRootDomain, true
	case "subdomain":
		return KindSubdomain, true
	case "host":
		if net.ParseIP(strings.TrimSpace(value)) != nil {
			return KindIP, true
		}
		return domainKind(value), true
	case "domain":
		return domainKind(value), true
	default:
		return "", false
	}
}

// domainKind classifies a hostname as a root_domain or a subdomain by comparing
// it to its registrable domain.
func domainKind(host string) AssetKind {
	h := normalizeHost(host)
	if h == registrableDomain(h) {
		return KindRootDomain
	}
	return KindSubdomain
}

// parentOf returns the (kind, value) of a node's immediate parent, or ("","") if
// it sits at the root of the hierarchy. It is the single place the parent-linking
// rules live.
func parentOf(kind AssetKind, value string, attrs map[string]string) (AssetKind, string) {
	switch kind {
	case KindRootDomain:
		return "", ""
	case KindSubdomain:
		if reg := registrableDomain(value); reg != "" && reg != value {
			return KindRootDomain, reg
		}
		return "", ""
	case KindIP:
		// An IP hangs off a hostname only when a tool tells us which one.
		if h := normalizeHost(attrs["host"]); h != "" {
			return domainKind(h), h
		}
		return "", ""
	case KindService:
		host, _ := splitHostPort(value)
		return hostNodeOf(host)
	case KindEndpoint:
		host, port := endpointHostPort(value)
		if host == "" {
			return "", ""
		}
		if port != "" {
			return KindService, host + ":" + port
		}
		return hostNodeOf(host)
	default:
		return "", ""
	}
}

// hostNodeOf returns the (kind, value) for a bare host string: an IP becomes an
// ip node, a hostname a root_domain or subdomain node.
func hostNodeOf(host string) (AssetKind, string) {
	if host == "" {
		return "", ""
	}
	if net.ParseIP(host) != nil {
		return KindIP, host
	}
	return domainKind(host), normalizeHost(host)
}

// normalizeFor canonicalizes a raw value for its kind so that equal assets dedup
// to one key regardless of how a tool spelled them.
func normalizeFor(kind AssetKind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch kind {
	case KindRootDomain, KindSubdomain:
		return normalizeHost(value)
	case KindIP:
		if ip := net.ParseIP(value); ip != nil {
			return ip.String()
		}
		return strings.ToLower(value)
	case KindService:
		host, port := splitHostPort(value)
		if host == "" {
			return strings.ToLower(value)
		}
		if port == "" {
			return normalizeHost(host)
		}
		return normalizeHost(host) + ":" + port
	case KindEndpoint:
		if u, err := url.Parse(value); err == nil && u.Host != "" {
			u.Scheme = strings.ToLower(u.Scheme)
			u.Host = strings.ToLower(u.Host)
			return u.String()
		}
		return strings.ToLower(value)
	default:
		return strings.ToLower(value)
	}
}

// normalizeHost lowercases a hostname and strips a trailing dot (the FQDN root).
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(h, ".")
}

// registrableDomain is a naive effective-TLD+1: the last two labels of the host.
// It does not consult the Public Suffix List, so multi-label suffixes (e.g.
// "co.uk") resolve to a two-label parent; that is acceptable for grouping and is
// documented as a known approximation.
func registrableDomain(host string) string {
	h := normalizeHost(host)
	if h == "" || net.ParseIP(h) != nil {
		return h
	}
	labels := strings.Split(h, ".")
	if len(labels) <= 2 {
		return h
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// splitHostPort splits a "host:port" service value, tolerating a bare host and
// bracketed IPv6. A missing port yields an empty port string.
func splitHostPort(value string) (host, port string) {
	value = strings.TrimSpace(value)
	if h, p, err := net.SplitHostPort(value); err == nil {
		return normalizeHost(h), p
	}
	// Bare host (no port) or an unparseable form: treat the whole thing as host.
	return normalizeHost(strings.Trim(value, "[]")), ""
}

// endpointHostPort extracts the host and effective port from an endpoint URL,
// defaulting the port from the scheme when it is implied.
func endpointHostPort(value string) (host, port string) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" {
		return "", ""
	}
	host = normalizeHost(u.Hostname())
	port = u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host, port
}

// Package cvematch is an OFFLINE version->CVE matcher. Given a software product
// and version — either passed explicitly or fingerprinted from an HTTP Server /
// X-Powered-By header — it scans tyto's local NVD CVE feeds and reports known
// CVEs whose CPE configurations cover that product/version.
//
// Findings here are INFERENCES: the NVD database says "this version is affected",
// not that we directly exercised the flaw. They are therefore emitted with
// Validated:false so the report's validated/candidate split treats them as
// candidates, in keeping with tyto's "confirm before you report" discipline.
//
// The feeds live as one .xz per year under ~/.tyto/feeds/nvd/CVE-YYYY.json.xz
// (or plain .json). Decompression uses the pure-Go github.com/ulikunitz/xz so
// nothing shells out. Feeds are streamed and only matching cve_items are kept,
// bounding memory regardless of feed size.
package cvematch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/dukotah/tyto/internal/action"
	"github.com/dukotah/tyto/internal/cveindex"
	"github.com/dukotah/tyto/internal/state"
)

type Tool struct{ http *http.Client }

func New() *Tool {
	return &Tool{http: &http.Client{Timeout: 8 * time.Second}}
}

func (t *Tool) Name() string              { return "cvematch" }
func (t *Tool) Category() action.Category { return action.CategoryScan }
func (t *Tool) MaxRisk() action.RiskLevel { return action.RiskLow }

// maxFindings caps how many CVEs we emit (the highest-CVSS ones).
const maxFindings = 20

// --- NVD feed shape (only the fields we consume) -------------------------

type nvdFeed struct {
	CVEItems []cveItem `json:"cve_items"`
}

type cveItem struct {
	ID             string          `json:"id"`
	Descriptions   []langValue     `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Configurations []configuration `json:"configurations"`
}

type langValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	V31 []cvssMetric `json:"cvssMetricV31"`
	V30 []cvssMetric `json:"cvssMetricV30"`
}

type cvssMetric struct {
	CVSSData cvssData `json:"cvssData"`
}

type cvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type configuration struct {
	Nodes []node `json:"nodes"`
}

type node struct {
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type cpeMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

func (t *Tool) Execute(ctx context.Context, a action.Action) (action.Result, error) {
	res := action.Result{ActionID: a.ID, Tool: t.Name(), StartedAt: time.Now().UTC()}
	finish := func() (action.Result, error) {
		res.FinishedAt = time.Now().UTC()
		return res, nil
	}

	info := func(title string) {
		res.Findings = append(res.Findings, state.Finding{
			ID: fmt.Sprintf("CM-%s-%d", a.ID, len(res.Findings)), Title: title,
			Severity: state.SeverityInfo, Target: a.Target, Tool: t.Name(),
			Validated: false, FoundAt: time.Now().UTC(),
		})
	}

	// 1. Resolve (product, version).
	product, version := t.resolveProduct(ctx, a)
	if product == "" {
		res.Success = true
		info("No product/version fingerprinted to match")
		res.Output = a.Target + ": no product fingerprinted"
		return finish()
	}
	product = strings.ToLower(product)

	// 2. Prefer the prebuilt SQLite index (instant). Built by `tyto feeds index`.
	if db := indexPath(a); db != "" {
		if ix, ierr := cveindex.Open(db); ierr == nil {
			matches, qerr := ix.Query(product, version)
			_ = ix.Close()
			if qerr == nil {
				if len(matches) > maxFindings {
					matches = matches[:maxFindings]
				}
				for _, m := range matches {
					res.Findings = append(res.Findings, state.Finding{
						ID:          fmt.Sprintf("CM-%s-%d", a.ID, len(res.Findings)),
						Title:       fmt.Sprintf("%s affects %s %s", m.CVEID, product, version),
						Severity:    sevFromString(m.Severity),
						Target:      a.Target,
						Description: truncate(m.Description, 200),
						CVSS:        m.Vector,
						Tool:        t.Name(),
						Validated:   false, // inference from version string
						FoundAt:     time.Now().UTC(),
					})
				}
				res.Success = true
				res.Output = fmt.Sprintf("product %s v%s: %d matching CVE(s) [indexed]", product, version, len(matches))
				return finish()
			}
		}
	}

	// 2b. No index — fall back to scanning the raw feed dir (slow on the full DB).
	dir, err := feedDir(a)
	if err == nil {
		_, err = os.Stat(dir)
	}
	files := feedFiles(dir)
	if err != nil || len(files) == 0 {
		res.Success = true
		info("No NVD feeds available (set TYTO_NVD or download feeds)")
		res.Output = fmt.Sprintf("product %s v%s: no NVD feeds at %s", product, version, dir)
		return finish()
	}

	// 3. Stream feeds, keeping only cve_items that match the queried product.
	var matched []cveItem
	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		items := loadFeed(f) // malformed/unreadable -> nil, skipped
		for _, it := range items {
			if cveMatches(it, product, version) {
				matched = append(matched, it)
			}
		}
	}

	// 4. Sort by CVSS desc and cap.
	sort.SliceStable(matched, func(i, j int) bool {
		return baseScore(matched[i]) > baseScore(matched[j])
	})
	if len(matched) > maxFindings {
		matched = matched[:maxFindings]
	}

	for _, it := range matched {
		sev, vector := severityAndVector(it)
		_, criteria := bestMatch(it, product, version)
		res.Findings = append(res.Findings, state.Finding{
			ID:          fmt.Sprintf("CM-%s-%d", a.ID, len(res.Findings)),
			Title:       fmt.Sprintf("%s affects %s %s", it.ID, product, version),
			Severity:    sev,
			Target:      a.Target,
			Description: truncate(enDescription(it), 200),
			Evidence:    criteria,
			CVSS:        vector,
			Tool:        t.Name(),
			Validated:   false, // inference from version string, not a confirmed vuln
			FoundAt:     time.Now().UTC(),
		})
	}

	res.Success = true
	res.Output = fmt.Sprintf("product %s v%s: %d matching CVE(s)", product, version, len(matched))
	return finish()
}

// resolveProduct returns (product, version), either from explicit params or by
// fingerprinting the target's HTTP Server / X-Powered-By header.
func (t *Tool) resolveProduct(ctx context.Context, a action.Action) (string, string) {
	if p := strings.TrimSpace(a.Params["product"]); p != "" {
		return p, strings.TrimSpace(a.Params["version"])
	}

	url := normalizeURL(a.Target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "tyto-cvematch")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if p, v, ok := parseServerHeader(resp.Header.Get("Server")); ok {
		return p, v
	}
	if p, v, ok := parseServerHeader(resp.Header.Get("X-Powered-By")); ok {
		return p, v
	}
	return "", ""
}

// parseServerHeader extracts ("nginx","1.18.0") from "nginx/1.18.0 (Ubuntu)".
// Returns ok=false when no product token is present. A product with no version
// still parses (version "").
func parseServerHeader(h string) (product, version string, ok bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", "", false
	}
	// First whitespace-delimited token, e.g. "nginx/1.18.0" out of "nginx/1.18.0 (Ubuntu)".
	token := strings.Fields(h)[0]
	name, ver, found := strings.Cut(token, "/")
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	if !found {
		return name, "", true
	}
	return name, strings.TrimSpace(ver), true
}

// indexPath resolves the prebuilt CVE index DB: a.Params["cve-index"] ->
// $TYTO_CVE_INDEX -> ~/.tyto/feeds/cve-index.db (only if it exists).
func indexPath(a action.Action) string {
	if p := strings.TrimSpace(a.Params["cve-index"]); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("TYTO_CVE_INDEX")); p != "" {
		return p
	}
	// If the caller pinned an explicit feed dir, honor it (scan those feeds) rather
	// than silently falling back to the global default index.
	if strings.TrimSpace(a.Params["nvd"]) != "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	def := filepath.Join(home, ".tyto", "feeds", "cve-index.db")
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return ""
}

// sevFromString maps an NVD CVSS baseSeverity to tyto's severity enum.
func sevFromString(s string) state.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return state.SeverityCritical
	case "HIGH":
		return state.SeverityHigh
	case "MEDIUM":
		return state.SeverityMedium
	case "LOW":
		return state.SeverityLow
	default:
		return state.SeverityInfo
	}
}

// feedDir resolves the NVD feed directory: a.Params["nvd"] -> $TYTO_NVD ->
// ~/.tyto/feeds/nvd.
func feedDir(a action.Action) (string, error) {
	if d := strings.TrimSpace(a.Params["nvd"]); d != "" {
		return d, nil
	}
	if d := strings.TrimSpace(os.Getenv("TYTO_NVD")); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".tyto", "feeds", "nvd"), nil
}

// feedFiles lists every *.json.xz and plain *.json in dir.
func feedFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".json.xz") || strings.HasSuffix(name, ".json") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Strings(out)
	return out
}

// loadFeed reads + (if needed) xz-decompresses + json-decodes one feed file,
// returning its cve_items. Any error yields nil (the caller skips it).
func loadFeed(path string) []cveItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".xz") {
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil
		}
		r = xr
	}

	var feed nvdFeed
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil
	}
	return feed.CVEItems
}

// cveMatches reports whether any vulnerable cpeMatch in the item covers the
// queried product+version.
func cveMatches(it cveItem, product, version string) bool {
	_, criteria := bestMatch(it, product, version)
	return criteria != ""
}

// bestMatch returns the cpeMatch and its criteria string for the first
// vulnerable entry that covers product+version, or ("", "") if none.
func bestMatch(it cveItem, product, version string) (cpeMatch, string) {
	for _, cfg := range it.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				cpeProduct, cpeVersion := parseCPE(m.Criteria)
				if cpeProduct == "" || !strings.EqualFold(cpeProduct, product) {
					continue
				}
				if cpeVersionMatches(m, cpeVersion, version) {
					return m, m.Criteria
				}
			}
		}
	}
	return cpeMatch{}, ""
}

// parseCPE returns (product, version) from a CPE 2.3 criteria string:
// cpe:2.3:part:vendor:product:version:...  -> fields 4 and 5.
func parseCPE(criteria string) (product, version string) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 {
		return "", ""
	}
	return parts[4], parts[5]
}

// cpeVersionMatches decides whether the queried version is covered, given the
// CPE's own version field plus any version-range bounds.
func cpeVersionMatches(m cpeMatch, cpeVersion, queried string) bool {
	hasRange := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""

	// Wildcard CPE version: rely on the range (or, with no range and no queried
	// version, treat as covering anything).
	if cpeVersion == "*" || cpeVersion == "-" || cpeVersion == "" {
		if !hasRange {
			return true
		}
		return inRange(m, queried)
	}

	// Concrete CPE version: an exact (case-insensitive) match wins.
	if strings.EqualFold(cpeVersion, queried) {
		return true
	}
	// Some feeds pin a base version yet still carry a range — honor it.
	if hasRange {
		return inRange(m, queried)
	}
	return false
}

// inRange tests queried against the [start..end] bounds; missing bounds are open.
func inRange(m cpeMatch, queried string) bool {
	if queried == "" {
		return false
	}
	if m.VersionStartIncluding != "" && compareVersions(queried, m.VersionStartIncluding) < 0 {
		return false
	}
	if m.VersionStartExcluding != "" && compareVersions(queried, m.VersionStartExcluding) <= 0 {
		return false
	}
	if m.VersionEndIncluding != "" && compareVersions(queried, m.VersionEndIncluding) > 0 {
		return false
	}
	if m.VersionEndExcluding != "" && compareVersions(queried, m.VersionEndExcluding) >= 0 {
		return false
	}
	return true
}

// compareVersions compares dotted versions segment by segment. Numeric segments
// compare numerically; if either side is non-numeric the pair compares as
// strings. A missing segment counts as 0 / "". Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		// A missing segment counts as "0" so that e.g. "1.18" == "1.18.0".
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xi, xErr := strconv.Atoi(x)
		yi, yErr := strconv.Atoi(y)
		if xErr == nil && yErr == nil {
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
			continue
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// severityAndVector maps the CVE's CVSS baseSeverity to a state.Severity and
// returns the vector string (preferring v3.1 over v3.0).
func severityAndVector(it cveItem) (state.Severity, string) {
	d, ok := primaryCVSS(it)
	if !ok {
		return state.SeverityInfo, ""
	}
	return severityFromString(d.BaseSeverity), d.VectorString
}

func primaryCVSS(it cveItem) (cvssData, bool) {
	if len(it.Metrics.V31) > 0 {
		return it.Metrics.V31[0].CVSSData, true
	}
	if len(it.Metrics.V30) > 0 {
		return it.Metrics.V30[0].CVSSData, true
	}
	return cvssData{}, false
}

func baseScore(it cveItem) float64 {
	if d, ok := primaryCVSS(it); ok {
		return d.BaseScore
	}
	return 0
}

func severityFromString(s string) state.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return state.SeverityCritical
	case "HIGH":
		return state.SeverityHigh
	case "MEDIUM":
		return state.SeverityMedium
	case "LOW":
		return state.SeverityLow
	default:
		return state.SeverityInfo
	}
}

func enDescription(it cveItem) string {
	for _, d := range it.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			return d.Value
		}
	}
	if len(it.Descriptions) > 0 {
		return it.Descriptions[0].Value
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "..."
}

// normalizeURL mirrors webcheck.normalizeURL: bare host -> http://, with the
// 443/8443 ports promoted to https://.
func normalizeURL(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	if strings.HasSuffix(target, ":443") || strings.HasSuffix(target, ":8443") {
		return "https://" + target
	}
	return "http://" + target
}

// WrapTransport implements tool.TransportWrapper: it lets the engine layer a
// RoundTripper (engagement traffic marker, evidence capture) under this tool's
// HTTP client without the tool knowing about it.
func (t *Tool) WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) {
	t.http.Transport = wrap(t.http.Transport)
}

// Package cveindex builds and queries a fast product->CVE lookup over tyto's
// local NVD CVE feeds. The NVD feeds (one CVE-YYYY.json[.xz] per year) hold
// ~250k CVEs in total; scanning them on every cvematch query takes >90s. This
// package does a one-time Build that flattens every vulnerable CPE match into a
// row in a SQLite table indexed by product, so a later Query is an indexed
// lookup (instant) instead of a full scan.
//
// It uses ncruces/go-sqlite3 (pure-Go, CGO-free SQLite via WASM) through the
// standard database/sql interface, mirroring internal/sqlstore, and
// ulikunitz/xz (pure-Go) to decode the .xz feed files.
package cveindex

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/ncruces/go-sqlite3/driver" // registers the "sqlite3" driver
	"github.com/ulikunitz/xz"
)

// batchSize is how many INSERTs accumulate in a transaction before it is
// committed and a fresh one begun. Committing in batches bounds memory/WAL
// growth across the ~250k-CVE corpus (which expands to far more CPE rows)
// without paying a per-row commit cost.
const batchSize = 5000

// descMaxLen caps the stored description length; full NVD descriptions are
// occasionally very long and we only need a human-readable summary.
const descMaxLen = 300

const schema = `
CREATE TABLE IF NOT EXISTS cve_cpe (
	product       TEXT,
	version_exact TEXT,
	vstart_incl   TEXT,
	vstart_excl   TEXT,
	vend_incl     TEXT,
	vend_excl     TEXT,
	cve_id        TEXT,
	cvss_score    REAL,
	cvss_severity TEXT,
	cvss_vector   TEXT,
	description   TEXT
);
CREATE INDEX IF NOT EXISTS idx_product ON cve_cpe(product);
`

// ---- NVD feed JSON shapes (only the fields we consume) ---------------------

type feed struct {
	CVEItems []cveItem `json:"cve_items"`
}

type cveItem struct {
	ID             string          `json:"id"`
	Descriptions   []description   `json:"descriptions"`
	Metrics        metrics         `json:"metrics"`
	Configurations []configuration `json:"configurations"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CVSSMetricV31 []cvssMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssMetric `json:"cvssMetricV30"`
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

// ---- Build -----------------------------------------------------------------

// Build flattens the NVD CVE feeds in feedsDir into the SQLite product->CVE
// index at dbPath and returns the number of rows inserted.
//
// It creates the cve_cpe table and idx_product index if absent, then DELETEs
// any existing rows so a rebuild is clean. It walks feedsDir for *.json.xz
// (xz-decoded) and *.json files; for each cve_item, every
// configurations[].nodes[].cpeMatch with vulnerable==true becomes one row
// (product = lowercased CPE field 4; version_exact = CPE field 5 unless "*"/"-";
// the four version bounds; the CVE id; CVSS preferring v3.1 then v3.0; a
// truncated English description). Inserts run in one prepared statement under a
// transaction committed every batchSize rows. Malformed or unreadable feed
// files are skipped (not fatal); ctx is honored between files and batches.
func Build(ctx context.Context, feedsDir, dbPath string) (rows int, err error) {
	db, err := sql.Open("sqlite3", "file:"+dbPath)
	if err != nil {
		return 0, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	defer db.Close()

	if _, err := db.Exec(schema); err != nil {
		return 0, fmt.Errorf("migrate sqlite %s: %w", dbPath, err)
	}
	if _, err := db.Exec(`DELETE FROM cve_cpe`); err != nil {
		return 0, fmt.Errorf("clear cve_cpe: %w", err)
	}

	entries, err := os.ReadDir(feedsDir)
	if err != nil {
		return 0, fmt.Errorf("read feeds dir %s: %w", feedsDir, err)
	}

	tx, stmt, err := beginInsert(db)
	if err != nil {
		return 0, err
	}
	// Ensure resources are released on any early return.
	committed := false
	defer func() {
		if !committed {
			stmt.Close()
			tx.Rollback() //nolint:errcheck // best effort on failure path
		}
	}()

	sinceCommit := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		isXZ := strings.HasSuffix(lower, ".json.xz")
		isJSON := strings.HasSuffix(lower, ".json")
		if !isXZ && !isJSON {
			continue
		}

		f, derr := decodeFeed(filepath.Join(feedsDir, name), isXZ)
		if derr != nil {
			// Skip malformed/unreadable feed files; not fatal.
			continue
		}

		for i := range f.CVEItems {
			if err := ctx.Err(); err != nil {
				return rows, err
			}
			item := &f.CVEItems[i]
			score, severity, vector := pickCVSS(item)
			desc := pickDescription(item)

			for _, cfg := range item.Configurations {
				for _, n := range cfg.Nodes {
					for _, m := range n.CPEMatch {
						if !m.Vulnerable {
							continue
						}
						product, versionExact := parseCriteria(m.Criteria)
						if product == "" {
							continue
						}
						if _, execErr := stmt.Exec(
							product, versionExact,
							m.VersionStartIncluding, m.VersionStartExcluding,
							m.VersionEndIncluding, m.VersionEndExcluding,
							item.ID, score, severity, vector, desc,
						); execErr != nil {
							return rows, fmt.Errorf("insert %s: %w", item.ID, execErr)
						}
						rows++
						sinceCommit++
						if sinceCommit >= batchSize {
							if tx, stmt, err = rotateTx(tx, stmt, db); err != nil {
								return rows, err
							}
							sinceCommit = 0
						}
					}
				}
			}
		}
	}

	stmt.Close()
	if err := tx.Commit(); err != nil {
		return rows, fmt.Errorf("final commit: %w", err)
	}
	committed = true
	return rows, nil
}

// beginInsert starts a transaction and prepares the row INSERT against it.
func beginInsert(db *sql.DB) (*sql.Tx, *sql.Stmt, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO cve_cpe
		(product, version_exact, vstart_incl, vstart_excl, vend_incl, vend_excl,
		 cve_id, cvss_score, cvss_severity, cvss_vector, description)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return nil, nil, fmt.Errorf("prepare insert: %w", err)
	}
	return tx, stmt, nil
}

// rotateTx commits the current batch and starts a fresh transaction+statement.
func rotateTx(tx *sql.Tx, stmt *sql.Stmt, db *sql.DB) (*sql.Tx, *sql.Stmt, error) {
	stmt.Close()
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("batch commit: %w", err)
	}
	return beginInsert(db)
}

// decodeFeed reads and JSON-decodes one feed file, xz-decompressing when isXZ.
func decodeFeed(path string, isXZ bool) (*feed, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var r io.Reader = file
	if isXZ {
		xr, err := xz.NewReader(file)
		if err != nil {
			return nil, err
		}
		r = xr
	}

	var f feed
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// parseCriteria splits a CPE 2.3 criteria string and returns the lowercased
// product (field 4) and the exact version (field 5, blanked when "*" or "-").
func parseCriteria(criteria string) (product, versionExact string) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 {
		return "", ""
	}
	product = strings.ToLower(parts[4])
	versionExact = parts[5]
	if versionExact == "*" || versionExact == "-" {
		versionExact = ""
	}
	return product, versionExact
}

// pickCVSS returns score/severity/vector, preferring CVSS v3.1 then v3.0.
func pickCVSS(item *cveItem) (score float64, severity, vector string) {
	if len(item.Metrics.CVSSMetricV31) > 0 {
		d := item.Metrics.CVSSMetricV31[0].CVSSData
		return d.BaseScore, d.BaseSeverity, d.VectorString
	}
	if len(item.Metrics.CVSSMetricV30) > 0 {
		d := item.Metrics.CVSSMetricV30[0].CVSSData
		return d.BaseScore, d.BaseSeverity, d.VectorString
	}
	return 0, "", ""
}

// pickDescription returns the English description, truncated to descMaxLen.
func pickDescription(item *cveItem) string {
	var val string
	for _, d := range item.Descriptions {
		if d.Lang == "en" {
			val = d.Value
			break
		}
	}
	if val == "" && len(item.Descriptions) > 0 {
		val = item.Descriptions[0].Value
	}
	if len(val) > descMaxLen {
		val = val[:descMaxLen]
	}
	return val
}

// ---- Query -----------------------------------------------------------------

// Match is a CVE that affects a queried product/version.
type Match struct {
	CVEID       string
	Severity    string
	Vector      string
	Description string
	Score       float64
}

// Index is an open handle to a built product->CVE database.
type Index struct {
	db *sql.DB
}

// Open opens an existing (or creatable) index database at dbPath.
func Open(dbPath string) (*Index, error) {
	db, err := sql.Open("sqlite3", "file:"+dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	return &Index{db: db}, nil
}

// Close releases the underlying database handle.
func (ix *Index) Close() error { return ix.db.Close() }

// Query returns the CVEs affecting the given product at the given version.
//
// It does an indexed lookup on product (lowercased), then decides per row
// whether version applies: an exact version match wins; otherwise, if any
// version bound is set, the queried version must fall within
// [vstart_incl/excl .. vend_incl/excl] (dotted-version comparison); rows with
// neither an exact version nor any bound match the product generally. Results
// are deduped by CVE id keeping the highest score and sorted by score
// descending (CVE id ascending as a tiebreaker for stable output).
func (ix *Index) Query(product, version string) ([]Match, error) {
	rows, err := ix.db.Query(`SELECT version_exact, vstart_incl, vstart_excl,
		vend_incl, vend_excl, cve_id, cvss_score, cvss_severity, cvss_vector,
		description FROM cve_cpe WHERE product = lower(?)`, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	best := map[string]Match{}
	for rows.Next() {
		var (
			versionExact, vstartIncl, vstartExcl, vendIncl, vendExcl string
			m                                                        Match
		)
		if err := rows.Scan(&versionExact, &vstartIncl, &vstartExcl,
			&vendIncl, &vendExcl, &m.CVEID, &m.Score, &m.Severity,
			&m.Vector, &m.Description); err != nil {
			return nil, err
		}
		if !versionApplies(version, versionExact, vstartIncl, vstartExcl, vendIncl, vendExcl) {
			continue
		}
		if prev, ok := best[m.CVEID]; !ok || m.Score > prev.Score {
			best[m.CVEID] = m
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Match, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].CVEID < out[j].CVEID
	})
	return out, nil
}

// versionApplies decides whether the queried version is covered by a row's
// exact version or version-range bounds. A row with no exact version and no
// bounds matches the product generally.
func versionApplies(query, exact, vstartIncl, vstartExcl, vendIncl, vendExcl string) bool {
	if exact != "" {
		return query == exact
	}
	hasBound := vstartIncl != "" || vstartExcl != "" || vendIncl != "" || vendExcl != ""
	if !hasBound {
		return true
	}
	if vstartIncl != "" && compareVersions(query, vstartIncl) < 0 {
		return false
	}
	if vstartExcl != "" && compareVersions(query, vstartExcl) <= 0 {
		return false
	}
	if vendIncl != "" && compareVersions(query, vendIncl) > 0 {
		return false
	}
	if vendExcl != "" && compareVersions(query, vendExcl) >= 0 {
		return false
	}
	return true
}

// compareVersions compares two dotted version strings. Segments are compared
// left to right; numeric segments are compared numerically, missing segments
// are treated as 0, and any segment that is not purely numeric (on either side)
// is compared as a string. It returns -1, 0, or 1.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var sa, sb string
		if i < len(as) {
			sa = as[i]
		}
		if i < len(bs) {
			sb = bs[i]
		}
		na, ea := strconv.Atoi(emptyToZero(sa))
		nb, eb := strconv.Atoi(emptyToZero(sb))
		if ea == nil && eb == nil {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		// At least one segment is non-numeric: compare as strings.
		if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func emptyToZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// Package sqlstore is the relational, resumable persistence layer for an
// engagement. It is the SQLite counterpart to the dep-free JSON snapshot in
// package store: same spirit (assets + findings + completed-action keys), but
// keyed by engagement and queryable, so host→service→vuln relationships and the
// AD attack-graph can be reconstructed with SQL when the planner needs them.
//
// It uses ncruces/go-sqlite3, a pure-Go (CGO-free) SQLite via WASM, through the
// standard database/sql interface.
package sqlstore

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/ncruces/go-sqlite3/driver" // registers the "sqlite3" driver

	"github.com/dukotah/tyto/internal/state"
)

// Store is a SQLite-backed engagement store. A single DB can hold many
// engagements; every row is scoped by engagement_id.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS assets (
	engagement_id TEXT NOT NULL,
	id            TEXT NOT NULL,
	type          TEXT,
	value         TEXT,
	attrs         TEXT,
	first_seen    TIMESTAMP,
	PRIMARY KEY (engagement_id, id)
);
CREATE TABLE IF NOT EXISTS findings (
	engagement_id TEXT NOT NULL,
	id            TEXT NOT NULL,
	title         TEXT,
	severity      INTEGER,
	target        TEXT,
	description   TEXT,
	evidence      TEXT,
	tool          TEXT,
	cvss          TEXT,
	validated     BOOL,
	found_at      TIMESTAMP
);
CREATE TABLE IF NOT EXISTS completed_actions (
	engagement_id TEXT NOT NULL,
	key           TEXT NOT NULL,
	PRIMARY KEY (engagement_id, key)
);
CREATE TABLE IF NOT EXISTS asset_graph (
	engagement_id TEXT NOT NULL,
	key           TEXT NOT NULL,
	kind          TEXT,
	value         TEXT,
	parent_key    TEXT,
	attrs         TEXT,
	first_seen    TIMESTAMP,
	PRIMARY KEY (engagement_id, key)
);
CREATE TABLE IF NOT EXISTS coverage (
	engagement_id TEXT NOT NULL,
	asset_ref     TEXT NOT NULL,
	kind          TEXT NOT NULL,
	ref           TEXT NOT NULL,
	direction     TEXT NOT NULL,
	touched_at    TIMESTAMP,
	PRIMARY KEY (engagement_id, asset_ref, kind, ref, direction)
);
`

// Open opens (creating if needed) the database at path and applies the
// CREATE TABLE IF NOT EXISTS migrations. Use "file::memory:" for an ephemeral
// in-memory DB.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// SaveState persists the engagement's assets, findings, and completed-action
// keys in a single transaction. Assets are upserted (attrs JSON-encoded);
// findings are deduped by (engagement_id, id); completed-action keys are
// inserted if absent. Calling it repeatedly with the same state is idempotent.
func (s *Store) SaveState(engagementID string, st *state.State, completedActions []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	for _, a := range st.Assets() {
		attrs, err := marshalAttrs(a.Attrs)
		if err != nil {
			return fmt.Errorf("marshal attrs for asset %s: %w", a.ID, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO assets (engagement_id, id, type, value, attrs, first_seen)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(engagement_id, id) DO UPDATE SET
			   type=excluded.type, value=excluded.value,
			   attrs=excluded.attrs, first_seen=excluded.first_seen`,
			engagementID, a.ID, a.Type, a.Value, attrs, a.FirstSeen,
		); err != nil {
			return fmt.Errorf("save asset %s: %w", a.ID, err)
		}
	}

	for _, f := range st.Findings() {
		if _, err := tx.Exec(
			`INSERT INTO findings
			 (engagement_id, id, title, severity, target, description, evidence, tool, cvss, validated, found_at)
			 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			 WHERE NOT EXISTS (
			   SELECT 1 FROM findings WHERE engagement_id=? AND id=?
			 )`,
			engagementID, f.ID, f.Title, int(f.Severity), f.Target,
			f.Description, f.Evidence, f.Tool, f.CVSS, f.Validated, f.FoundAt,
			engagementID, f.ID,
		); err != nil {
			return fmt.Errorf("save finding %s: %w", f.ID, err)
		}
	}

	for _, key := range completedActions {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO completed_actions (engagement_id, key) VALUES (?, ?)`,
			engagementID, key,
		); err != nil {
			return fmt.Errorf("save completed action %q: %w", key, err)
		}
	}

	for _, n := range st.Graph() {
		attrs, err := marshalAttrs(n.Attrs)
		if err != nil {
			return fmt.Errorf("marshal attrs for graph node %s: %w", n.Key, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO asset_graph (engagement_id, key, kind, value, parent_key, attrs, first_seen)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(engagement_id, key) DO UPDATE SET
			   kind=excluded.kind, value=excluded.value,
			   parent_key=excluded.parent_key, attrs=excluded.attrs,
			   first_seen=excluded.first_seen`,
			engagementID, n.Key, string(n.Kind), n.Value, n.ParentKey, attrs, n.FirstSeen,
		); err != nil {
			return fmt.Errorf("save graph node %s: %w", n.Key, err)
		}
	}

	for _, c := range st.Coverage() {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO coverage
			 (engagement_id, asset_ref, kind, ref, direction, touched_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			engagementID, c.AssetRef, string(c.Kind), c.Ref, c.Direction, c.At,
		); err != nil {
			return fmt.Errorf("save coverage anchor %q: %w", c.Ref, err)
		}
	}

	return tx.Commit()
}

// LoadState reads back the persisted assets, findings, completed-action keys,
// normalized asset graph, and coverage anchors for an engagement.
func (s *Store) LoadState(engagementID string) (assets []*state.Asset, findings []state.Finding, completedActions []string, graph []*state.GraphNode, coverage []state.CoverageAnchor, err error) {
	assets, err = s.loadAssets(engagementID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	findings, err = s.loadFindings(engagementID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	completedActions, err = s.loadCompletedActions(engagementID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	graph, err = s.loadGraph(engagementID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	coverage, err = s.loadCoverage(engagementID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return assets, findings, completedActions, graph, coverage, nil
}

func (s *Store) loadAssets(engagementID string) ([]*state.Asset, error) {
	rows, err := s.db.Query(
		`SELECT id, type, value, attrs, first_seen FROM assets
		 WHERE engagement_id=? ORDER BY id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*state.Asset
	for rows.Next() {
		var (
			a     state.Asset
			attrs sql.NullString
		)
		if err := rows.Scan(&a.ID, &a.Type, &a.Value, &attrs, &a.FirstSeen); err != nil {
			return nil, err
		}
		a.Attrs, err = unmarshalAttrs(attrs)
		if err != nil {
			return nil, fmt.Errorf("unmarshal attrs for asset %s: %w", a.ID, err)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (s *Store) loadFindings(engagementID string) ([]state.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, title, severity, target, description, evidence, tool, cvss, validated, found_at
		 FROM findings WHERE engagement_id=? ORDER BY rowid`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []state.Finding
	for rows.Next() {
		var (
			f   state.Finding
			sev int
		)
		if err := rows.Scan(&f.ID, &f.Title, &sev, &f.Target, &f.Description,
			&f.Evidence, &f.Tool, &f.CVSS, &f.Validated, &f.FoundAt); err != nil {
			return nil, err
		}
		f.Severity = state.Severity(sev)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) loadCompletedActions(engagementID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT key FROM completed_actions WHERE engagement_id=? ORDER BY key`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (s *Store) loadGraph(engagementID string) ([]*state.GraphNode, error) {
	rows, err := s.db.Query(
		`SELECT key, kind, value, parent_key, attrs, first_seen FROM asset_graph
		 WHERE engagement_id=? ORDER BY key`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*state.GraphNode
	for rows.Next() {
		var (
			n     state.GraphNode
			kind  string
			attrs sql.NullString
		)
		if err := rows.Scan(&n.Key, &kind, &n.Value, &n.ParentKey, &attrs, &n.FirstSeen); err != nil {
			return nil, err
		}
		n.Kind = state.AssetKind(kind)
		n.Attrs, err = unmarshalAttrs(attrs)
		if err != nil {
			return nil, fmt.Errorf("unmarshal attrs for graph node %s: %w", n.Key, err)
		}
		out = append(out, &n)
	}
	return out, rows.Err()
}

func (s *Store) loadCoverage(engagementID string) ([]state.CoverageAnchor, error) {
	rows, err := s.db.Query(
		`SELECT asset_ref, kind, ref, direction, touched_at FROM coverage
		 WHERE engagement_id=? ORDER BY touched_at, ref`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []state.CoverageAnchor
	for rows.Next() {
		var (
			c    state.CoverageAnchor
			kind string
		)
		if err := rows.Scan(&c.AssetRef, &kind, &c.Ref, &c.Direction, &c.At); err != nil {
			return nil, err
		}
		c.Kind = state.CoverageKind(kind)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Into loads the engagement and replays its assets, findings, graph, and
// coverage into st, returning the completed-action keys. Assets/findings go
// through AddAsset/AddFinding so dedup rules apply (and the graph/coverage are
// re-derived from them); the persisted graph nodes are then applied verbatim via
// AddGraphNode to restore any program-computed links, and coverage anchors are
// replayed via AddCoverage. It mirrors store.Snapshot.Into for the SQLite store.
func (s *Store) Into(engagementID string, st *state.State) ([]string, error) {
	assets, findings, completed, graph, coverage, err := s.LoadState(engagementID)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		st.AddAsset(a)
	}
	for _, f := range findings {
		st.AddFinding(f)
	}
	for _, n := range graph {
		st.AddGraphNode(n)
	}
	for _, c := range coverage {
		st.AddCoverage(c)
	}
	return completed, nil
}

// marshalAttrs encodes an asset's Attrs map to JSON text. A nil/empty map is
// stored as NULL so it round-trips back to nil.
func marshalAttrs(attrs map[string]string) (sql.NullString, error) {
	if len(attrs) == 0 {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

// unmarshalAttrs decodes the stored JSON text back into an Attrs map. NULL or
// empty decodes to nil (matching what marshalAttrs stored).
func unmarshalAttrs(attrs sql.NullString) (map[string]string, error) {
	if !attrs.Valid || attrs.String == "" {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(attrs.String), &m); err != nil {
		return nil, err
	}
	return m, nil
}

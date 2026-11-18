package attack

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

// embeddedJSON is the curated offline technique set authored at
// data/techniques.json. It is the no-network default used by Embedded.
//
//go:embed data/techniques.json
var embeddedJSON []byte

// embeddedFile is the on-disk JSON shape of the curated set: a flat array of
// technique records.
type embeddedRecord struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactics     []string `json:"tactics"`
	Description string   `json:"description"`
	URL         string   `json:"url"`
}

var (
	embeddedOnce sync.Once
	embeddedCat  *Catalog
	embeddedErr  error
)

// Embedded returns a Catalog built from the curated offline technique set
// embedded in the binary (~50 of the most common enterprise techniques). It is
// the default source so tyto blue works with no network access.
//
// To use the full official ATT&CK catalog instead, fetch the enterprise-attack
// STIX 2.1 bundle and pass it to LoadSTIX.
//
// The embedded data is parsed once and cached; the returned Catalog must be
// treated as read-only. Embedded panics if the baked-in data is malformed,
// which can only happen from a build-time authoring error.
func Embedded() *Catalog {
	embeddedOnce.Do(func() {
		var recs []embeddedRecord
		if err := json.Unmarshal(embeddedJSON, &recs); err != nil {
			embeddedErr = fmt.Errorf("attack: parse embedded catalog: %w", err)
			return
		}
		techs := make([]Technique, 0, len(recs))
		for _, r := range recs {
			techs = append(techs, Technique{
				ID:          r.ID,
				Name:        r.Name,
				Tactics:     r.Tactics,
				Description: r.Description,
				URL:         r.URL,
			})
		}
		embeddedCat = newCatalog(techs)
	})
	if embeddedErr != nil {
		panic(embeddedErr)
	}
	return embeddedCat
}

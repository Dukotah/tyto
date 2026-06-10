// Package webui holds the embedded single-page console served by `tyto serve`.
package webui

import _ "embed"

//go:embed index.html
var Index []byte

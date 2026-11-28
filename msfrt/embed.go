//go:build embedruntime

package msfrt

import _ "embed"

// runtime.zip is produced by scripts/build-runtime.ps1. Keeping it optional
// (build tag) means a plain `go build ./...` works without the ~300 MB payload.
//
//go:embed runtime.zip
var embeddedPayload []byte

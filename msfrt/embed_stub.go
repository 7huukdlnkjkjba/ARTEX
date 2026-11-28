//go:build !embedruntime

package msfrt

// embeddedPayload stays nil in a normal build: the runtime travels as an exe
// trailer instead (scripts/append-payload.ps1). Build with `-tags embedruntime`
// after placing runtime.zip in this directory to bake it into the binary.
var embeddedPayload []byte

// Package version holds build metadata, injected via -ldflags at build time.
package version

// Version is the build version. Overridden via -ldflags in the Makefile.
var Version = "dev"

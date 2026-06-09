// Command tyto is the CLI entrypoint for the AI-orchestrated authorized
// penetration-testing platform.
package main

import (
	"context"
	"os"
)

func main() {
	// cobra prints the error itself; we just set the exit code.
	if err := newRootCmd().ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

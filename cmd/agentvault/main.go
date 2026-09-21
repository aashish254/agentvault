package main

import (
	"os"

	"github.com/aashish/agentvault/internal/cli"
)

func main() {
	// Busybox dispatch: invoked via a shim symlink (unix) → act as the
	// shimmed binary. Windows uses the explicit `__shim` subcommand.
	if handled, code := cli.ShimDispatch(); handled {
		os.Exit(code)
	}
	os.Exit(cli.Execute())
}

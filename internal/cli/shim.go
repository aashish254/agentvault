package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/shim"
)

// newShimCmd is the hidden entrypoint every shimmed binary hits.
// On unix the shim symlink execs agentvault with argv[0]=<binary name>;
// main() rewrites that into __shim form. On Windows the .cmd wrapper
// calls this subcommand directly.
func newShimCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__shim <binary> [args...]",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			exitCode = shim.Handle(args[0], args[1:])
			if exitCode != 0 {
				// Return a silent error so Execute doesn't print usage;
				// the shim already wrote the explanation to stderr.
				return errShimExit
			}
			return nil
		},
	}
}

// errShimExit marks "shim finished with non-zero exit"; Execute must not
// print an additional error message for it.
var errShimExit = fmt.Errorf("shim exit")

package cli

import (
	"context"
	"errors"

	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/ui"
)

// Run executes one command in this process, as Execute would, with the run's
// streams replaced. A failure is written to s.Err the way the terminal would see
// it, and the exit code the process would have ended with is returned.
//
// It exists so a server can answer a command without starting a second process
// and without a terminal: the whole command layer - argument checks, the
// confirmation policy, --dry-run, output formats - is the one the CLI runs.
func Run(ctx context.Context, args []string, s app.Streams) (code int, err error) {
	args = preprocessArgs(append([]string{"proton"}, args...))[1:]
	if err := unknownSubcommand(newRootIO(s), args); err != nil {
		if s.Err != nil {
			ui.WriteError(s.Err, err, ui.StyleFor(s.Err, ui.ColorNever), false)
		}
		return exitCode(err), err
	}
	root := newRootIO(s)
	root.SetArgs(args)
	root.SetOut(s.Out)
	root.SetErr(s.Err)
	_, err = root.ExecuteContextC(ctx)
	if err == nil {
		return 0, nil
	}
	var hvErr *proton.HumanVerificationError
	if errors.As(err, &hvErr) {
		err = hvFinalError(hvErr, app.FromOrNil(root.Context()))
	}
	if s.Err != nil {
		ui.WriteError(s.Err, err, ui.StyleFor(s.Err, ui.ColorNever), false)
	}
	return exitCode(err), err
}

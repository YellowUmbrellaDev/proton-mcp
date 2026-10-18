package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/roman-16/proton-cli/internal/mcpauth"
	"github.com/roman-16/proton-cli/internal/profile"
)

// RunnerFromToken makes a server multi-user: each call acts as the Proton profile
// named by the subject of the verified bearer token it arrived with, and as no
// one else. defaults carries everything but the profile (zone, confirmation).
//
// The subject becomes a profile name, and a profile name becomes a file name, so
// it is parsed with profile.Parse and anything that is not a plain name is
// refused rather than cleaned up. The empty subject is refused too, where
// profile.Parse would take it for the default profile: a token without a subject
// must never fall through to someone's session.
func RunnerFromToken(defaults Runner) func(context.Context) (Runner, error) {
	return func(ctx context.Context) (Runner, error) {
		info := auth.TokenInfoFromContext(ctx)
		if info == nil {
			return Runner{}, errors.New("the request carries no verified token")
		}
		if info.UserID == "" {
			return Runner{}, errors.New("the token names no subject")
		}
		name, err := profile.Parse(info.UserID)
		if err != nil {
			return Runner{}, fmt.Errorf("the token's subject is not a valid profile name: %w", err)
		}
		r := defaults
		r.Profile = name.String()
		return r, nil
	}
}

// AllowByScope enforces the scopes of the verified token: any tool needs
// ScopeRead or ScopeWrite, and a tool that changes anything needs ScopeWrite.
func AllowByScope() func(ctx context.Context, t Tool) error {
	return func(ctx context.Context, t Tool) error {
		info := auth.TokenInfoFromContext(ctx)
		if info == nil {
			return errors.New("the request carries no verified token")
		}
		write := slices.Contains(info.Scopes, mcpauth.ScopeWrite)
		if !write && !slices.Contains(info.Scopes, mcpauth.ScopeRead) {
			return fmt.Errorf("this connection has no Proton access: its grant holds neither %s nor %s. Disconnect and connect again to grant access",
				mcpauth.ScopeRead, mcpauth.ScopeWrite)
		}
		if t.Mutating && !write {
			return fmt.Errorf("%s changes data, and this connection was granted read-only access (%s). Disconnect and connect again, approving write access (%s), to allow it",
				t.Name, mcpauth.ScopeRead, mcpauth.ScopeWrite)
		}
		return nil
	}
}

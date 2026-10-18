package mcpserver

import (
	"os"
	"testing"
)

// The live tests run against a real account, so nothing about that account is
// written in the repository: its addresses and the official CLI binary come from
// the environment, and a test that needs one skips when it is not set.
//
//	PROTON_MCP_LIVE            profile to run as (turns the live tests on)
//	PROTON_MCP_OWN_ADDRESS     an address of that account: the only one mail is ever sent to
//	PROTON_MCP_PRIMARY_ADDRESS the account's primary address
//	PROTON_MCP_OTHER_ADDRESS   another address of the account, for tools that name a second one
//	PROTON_OFFICIAL_CLI        the unmodified `proton` binary, for comparing and for clean-up

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s is not set", name)
	}
	return v
}

func ownAddress(t *testing.T) string     { return liveEnv(t, "PROTON_MCP_OWN_ADDRESS") }
func primaryAddress(t *testing.T) string { return liveEnv(t, "PROTON_MCP_PRIMARY_ADDRESS") }
func otherAddress(t *testing.T) string   { return liveEnv(t, "PROTON_MCP_OTHER_ADDRESS") }

func officialBinary(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"PROTON_OFFICIAL_CLI", "PROTON_PARITY_CLI"} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	t.Skip("PROTON_OFFICIAL_CLI is not set")
	return ""
}

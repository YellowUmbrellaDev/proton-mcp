package mcpserver

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newForTest() (*mcp.Server, []Tool, error) {
	return New(Config{
		Version: "test",
		Runner:  func(context.Context) (Runner, error) { return Runner{}, errors.New("no session in this test") },
	})
}

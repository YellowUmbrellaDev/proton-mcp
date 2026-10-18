# proton-mcp

`proton-mcp` serves the CLI's commands as MCP tools, one tool per command. It runs three ways.

| Mode | Flags | For |
|---|---|---|
| stdio | `-stdio` | one local client; acts as `-profile` |
| static token | `-token-file F` | one account over HTTP, behind a shared bearer token |
| OAuth | `-oauth -issuer URL -state F -key-file F` | many people, each acting as their own Proton session |

`-oauth` cannot be combined with `-token-file` or `-stdio`.

## Flags

| Flag | Meaning |
|---|---|
| `-addr` | HTTP listen address, default `127.0.0.1:8080` |
| `-profile` | saved session used in stdio and static-token modes, default `default` |
| `-token-file` | file holding the bearer token (static mode) |
| `-oauth` | serve many people behind OAuth |
| `-issuer` | public base URL, e.g. `https://proton-mcp.example.com`, no path. The MCP endpoint is `<issuer>/mcp` |
| `-state` | file where registered clients, grants and tokens are kept |
| `-key-file` | key that seals the state: at least 32 bytes, or base64 of 32 bytes. A longer secret is hashed to 32 bytes. Startup is refused if it is shorter |
| `-zone` | IANA zone every command works in, default `UTC` |
| `-confirm` | confirmation policy handed to every command |
| `-enable-api` | expose the raw `api` command |
| `-max-calls-per-minute`, `-burst` | tool-call rate limit, default 30 a minute with a burst of 5 (0 disables it) |
| `-list` | print the tools and exit |

Every HTTP mode serves `GET /healthz`, which answers `200 ok` without authentication, for container health checks.

## OAuth mode

One mux serves everything:

- `/mcp` is the MCP endpoint. It requires a bearer token issued by the authorization server and answers `401` with a `WWW-Authenticate` header pointing at the resource metadata otherwise.
- Everything else (`/.well-known/*`, `/register`, `/authorize`, the login pages, `/token`, `/revoke`) belongs to the authorization server in `internal/mcpauth`.

A client discovers the server, registers, and sends the person to the login page. Proton offers no OAuth to third parties, so the login is Proton's "sign in with another device": the person approves a code in a Proton app they are already signed in on. The server then gives the client a code, which becomes an access and a refresh token. The token's subject is the name of the saved Proton session; every tool call runs as that profile.

On start the server prints the issuer, the tool count and the listen address. It never prints keys, tokens or codes.

### Scopes

| Scope | Allows |
|---|---|
| `proton:read` | tools that only read |
| `proton:write` | everything, including tools that change data (any tool marked mutating, and `send`, `delete`, `share` and the like) |

A token with neither scope can call nothing. A read-only grant that calls a changing tool gets an error saying so and how to reconnect with write access; the command is never run. Irreversible tools additionally need `confirm: true` on the call, as in every mode.

## Security model

- **The account password never reaches the server.** Sign-in is approved on another device already signed in to Proton.
- **One process, many subjects.** The profile for a call is derived only from the verified token's subject (`mcpserver.RunnerFromToken`). A request without a verified token, or with a subject that is not a plain profile name (empty, `a/b`, `../x`, a leading dot, longer than 64 characters), is refused. A subject never becomes a path unvalidated, and one person's call can never be handed another person's profile.
- **Sessions live under the config dir** (`$XDG_CONFIG_HOME/proton-cli`, one file per profile), written by the login. The state file (`-state`) holds clients, grants and tokens, sealed with `-key-file`. Keep both on a private volume, mode 0600, and back them up together; losing the key invalidates the state.
- **Time zone.** Commands adopt their zone as the process-global `time.Local`. The server sets it once at startup from `-zone` and passes the same zone to every call, so concurrent calls write nothing to it (`adoptZone` also takes a lock and skips the write when the zone is unchanged).
- **Rate limit.** Tool calls are spaced across all users to keep the traffic from looking like abuse to Proton.
- Keep the server behind TLS (the issuer should be `https`); the issuer URL is what clients are told to trust.

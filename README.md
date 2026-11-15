# github-core-clone-01 — a GitHub-compatible git forge

A single-process forge that speaks GitHub's four surfaces over one in-memory store,
written in TypeScript on Node's standard library alone — no dependencies, no `git`
binary, no network at run time.

## Surfaces

- **Git smart HTTP** (`/<owner>/<repo>.git/info/refs`, `git-upload-pack`,
  `git-receive-pack`): protocol v0 and v2, including ls-refs, shallow/deepen
  fetches, wait-for-done negotiation, sideband framing, pack reading and writing
  with OFS/REF delta resolution, and fast-forward enforcement with report-status.
- **REST v3** (`/api/v3`): repositories, branches, git refs, commits, contents,
  labels, issues, comments, pull requests, pull-request files and squash merges,
  with GitHub's status codes, `Link` pagination and JSON error bodies.
- **GraphQL v4** (`/api/graphql`): the queries and mutations `gh` and
  github-mcp-server send — viewer, repository, issues with cursor pagination,
  pull requests, `node(id:)`, `__type` introspection, batched operations, and the
  create/close/merge mutations.
- **MCP** (`/mcp`): JSON-RPC over streamable HTTP with `server/discover`,
  `tools/list` and six tools (`create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request`) acting on the same
  store as every other surface.

## Running

The platform runs `node /bot/main.ts` (Node 22.18+ strips the types). `main.ts`
binds an ephemeral port, registers it with the env at `MAKEFUN_ENV_URL`, and waits
for the env to say the trial is done. State lives in process memory only.

Layout: `main.ts` is the lifecycle; `app.ts` is the whole forge.

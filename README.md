# archscan

Static analysis for a Python repo: modules, call graph, and traces from
sources (CLI input, env vars, files, network, database) to risky sinks
(`subprocess`, `eval`, `pickle.load`, ...).

## Install

```sh
uv sync
```

## CLI usage

```sh
uv run archscan <path> [-o FILE] [--trace KIND] [--with-jev]
```

- `<path>`: root directory of the repo to scan.
- `-o FILE`: write the report to `FILE` instead of stdout. `.json` writes the
  machine-readable report (see below); `.html` writes a standalone HTML
  page; any other suffix writes the plain-text report.
- `--trace KIND`: only trace one source kind (e.g. `env`), instead of all
  kinds in the catalog.
- `--with-jev`: classify each module's role and whether it handles auth,
  using Jev (see [typesafe-ai](https://typesafe.ai)). Needs `TYPESAFE_API_KEY`;
  without it, `--with-jev` exits with an error. Without this flag, archscan
  never calls TypeSafe. Capabilities (`touches_db`, `touches_network`,
  `reads_user_input`, `reads_secrets`) are derived from the code itself and
  always appear, with or without `--with-jev`.

Example:

```sh
uv run archscan . -o report.json
```

## Configuration

### `archscan.toml`

Optional, at the repo root. Controls which directories the scan skips:

```toml
[scan]
skip = ["vendor"]   # extra directory names to skip
keep = ["docs"]     # remove a name from the default skip set
```

The default skip set covers `.venv`, `venv`, `__pycache__`, `.git`,
`node_modules`, `.tox`, `build`, `dist`, `doc`, `docs`, `benchmarks`,
`examples`.

### `sources.toml`

Optional, at the repo root. Adds project-specific source/sink entries on
top of the built-in catalog (`archscan/catalog.toml`):

```toml
[[source]]
kind = "config"
match = ["myapp.settings.load"]

[[sink]]
kind = "custom_exec"
match = ["myapp.runner.run_untrusted"]
```

## JSON output

`archscan . -o report.json` writes a stable, versioned JSON report
(`archscan/export.py`): project summary, modules, functions, call graph
edges, traces, and coverage. Use this for scripting or feeding the data to
another tool.

Each trace finding has a `path`: the functions the value passed through, in
order, via calls and returns, ending at `function`. This is not a call
chain; use the MCP `path_between` tool for that.

## MCP server

`archscan-mcp` exposes the same analysis as MCP tools, for use by an agent:
`overview`, `module`, `callers`, `callees`, `trace`, `path_between`,
`search`. It scans a repo once per session and caches the result, keyed by
resolved root path, rescanning only when a `.py` file changes. Every tool
takes a `path` (the repo root) and returns a JSON-safe dict; list fields
are capped (default 50) with `truncated`/`total` when cut.

Capabilities are always in tool results, derived from the code. Set
`ARCHSCAN_WITH_JEV=1` and `TYPESAFE_API_KEY` to also classify each module's
`role` and add `handles_auth` to its capabilities; MCP has no `--with-jev`
flag, so this env var is the only switch. Without `ARCHSCAN_WITH_JEV=1`,
archscan never calls TypeSafe and `role` is `null`.

Add it to Claude Code:

```sh
claude mcp add archscan -- uv run --directory /path/to/archscan archscan-mcp
```

Logs go to stderr only, at `WARNING` by default. Set `ARCHSCAN_LOG` (e.g.
`INFO`, `DEBUG`) to change the level.

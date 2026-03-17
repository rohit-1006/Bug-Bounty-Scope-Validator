## [2.1.0] - 2024-01-15

### Added
- **Secure credential storage** (`--config`) — tokens stored in `~/.scope_checker/config.yaml` with 0600 permissions, never exposed in process list
- **Scope diffing** — every import shows `+added` / `-removed` assets automatically
- **Wildcard strict mode** (`--wildcard-strict`) — `*.example.com` won't match `example.com` apex; per-program, persisted in DB
- **Sample scope generator** (`--init FILE`) — creates a working YAML template
- **Database auto-backup** — before every destructive operation, keeps last 10 in `~/.scope_checker/backups/`
- **Scope refresh** (`--update`) — re-fetches scope from original API platform
- **IDN/punycode support** — international domain names handled properly in sanitizer
- **ConfigManager class** — hierarchical config with nested key access
- **ScopeDiff engine** — compares old vs new scope, outputs structured diff
- **DB schema v3** — adds `wildcard_strict` column to programs table
- **`--backup` command** — manual database backup
- **127 test assertions** (up from 105)

### Changed
- API credentials now loaded from config file first, then env vars, then CLI flags
- All destructive DB operations trigger auto-backup
- Import commands display diff automatically
- `--update` detects original platform from stored program data

### Fixed
- API tokens visible in `ps aux` when passed via `--api-token`
- `*.example.com` matching `example.com` apex caused false positives for strict programs
- Re-importing scope with no changes gave no feedback
- IDN domains with non-ASCII characters caused sanitizer errors
- Missing SIGPIPE handler caused tracebacks when piping to `head`

## [2.0.0] - 2024-01-10

### Added
- **127-assertion self-test suite** (`--self-test`)
- **IPv6 support** — full IPv6Address + IPv6Network matching with CIDR
- **Logging framework** — Python logging to stderr + file at `~/.scope_checker/scope_checker.log`
- **Database schema versioning** — `schema_version` table with automatic migrations
- **Concurrent batch checking** — `check_batch()` with ThreadPoolExecutor
- **Input sanitization** — `InputSanitizer` class with max lengths, null byte removal
- **API error handling** — specific messages for 401, 404, 429 status codes
- **Rate limiting** — 1-second delay between Bugcrowd API calls
- **Scope staleness detection** — warns when scope >30 days old
- **Duplicate prevention** — `add_entry()` rejects existing assets
- **Program search** (`--search QUERY`)
- **Database stats** (`--stats`)
- **Asset removal** (`--remove-asset`)
- **BrokenPipeError handling** — clean exit when piping to `head`/`grep`
- **SIGPIPE signal handler**
- **WAL journal mode** for SQLite concurrency
- **Port+domain combined validation** in URL checker

### Changed
- IP ranges auto-swap if start > end
- URL checker validates port against port rules when restrictions exist
- Database indexes added for scope_type and program name

## [1.0.0] - 2024-01-05

### Initial Release
- Core matching engine (domain, wildcard, CIDR, IP, URL, port)
- 5 parsers (HackerOne API, Bugcrowd API, YAML, JSON, text)
- SQLite database for persistent scope storage
- Pipe-friendly filtering (`--filter`, `--filter-out`)
- 3 export formats (YAML, JSON, text)
- Exit codes (0=in-scope, 1=out-of-scope)
- JSON output mode
- Bounty tracking with 💰 indicator
- Color output with terminal detection

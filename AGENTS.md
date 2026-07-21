# monux — agent guidance

## Versioning (user-mandated policy)

The crate version in `Cargo.toml` follows semver:

- **Protocol break → MAJOR.** A protocol break is any change that bumps
  `PROTOCOL_VERSION` in `src/msgs/shared.rs`. Never bump
  `PROTOCOL_VERSION` without also bumping the MAJOR crate version.
- **User-facing feature → MINOR.**
- **Fix / refactor / internal change → PATCH.**

Bump in the same commit as the change, or before pushing — the
auto-updater builds every master commit, so master must always carry a
version that reflects its changes. `--version` and `--help` display the
protocol version; the client update gate keys on `PROTOCOL_VERSION`, so
keeping these in lockstep matters.

History: the version sat at 0.3.3 through the monux rename and the v7→v8
protocol break; it was bumped straight to 1.0.0 on 2026-07-21 when this
policy was adopted.

## House rules

- `cargo build --release` must finish with zero warnings; `cargo test`
  green before committing.
- Commit messages: no line wrapping; one idea per paragraph via multiple
  `-m` flags.
- `PLAN.md` tracks the multi-phase improvement plan and its per-phase
  review checkpoints.

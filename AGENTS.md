# monux — agent guidance

## Versioning (user-mandated policy)

The crate version in `Cargo.toml` follows semver:

- **Protocol break → MAJOR.** A protocol break is any change that bumps
  `PROTOCOL_VERSION` in `src/msgs/shared.rs`. Never bump
  `PROTOCOL_VERSION` without also bumping the MAJOR crate version.
- **User-facing feature → MINOR.**
- **Fix / refactor / internal change → PATCH.**

Bump in the same commit as the change, or before pushing — master must
always carry a version that reflects its changes. `--version` and
`--help` display the protocol version; the client update gate keys on
`PROTOCOL_VERSION`, so keeping these in lockstep matters.

**A release is not published until it is TAGGED.** Release signing is
configured (`RELEASE_SIGNING_KEY` in `src/update.rs`), so the updater —
the daily check and `mx update` alike — only ever builds the newest
SIGNED TAG, never master tip: an untagged push is invisible to it, and
it reports "already up to date" no matter how far master has moved
(`--force` doesn't help either; it just rebuilds the old tag). After
pushing a version bump:

```
git tag -s v<X.Y.Z> -m 'monux v<X.Y.Z>' <commit>
git push origin v<X.Y.Z>
```

Sign with the release key (`~/.ssh/monux-release`, configured as
`user.signingkey` with `gpg.format=ssh`); use ssh-askpass for the
passphrase prompt when there is no agent.

History: the version sat at 0.3.3 through the monux rename and the v7→v8
protocol break; it was bumped straight to 1.0.0 on 2026-07-21 when this
policy was adopted.

## House rules

- `cargo build --release` must finish with zero warnings; `cargo test`
  green before committing.
- `cargo clippy --all-targets -- -D warnings` must be clean too. The tree
  was brought to zero on 2026-08-07; keeping it there is far cheaper than
  the next cleanup. Where a lint is genuinely wrong for the code, add a
  targeted `#[allow]` with a comment saying why — never a blanket allow.
- Commit messages: no line wrapping; one idea per paragraph via multiple
  `-m` flags.
- `PLAN.md` tracks the multi-phase improvement plan and its per-phase
  review checkpoints.

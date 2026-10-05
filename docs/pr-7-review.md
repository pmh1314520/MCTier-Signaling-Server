# PR #7 review

Audited source: `4d9e43cd17bcae7df1c614343b20545195767e7e` against server `main` `1c0054613062848bc44c6db1c811eecd0fdaa4c8`.

## Accepted

- Extracted transport delivery, configuration, signed registration, and host moderation into focused modules without changing the WebSocket message inventory or payload behavior.
- Verified all ten extracted transport function bodies against the original implementation.
- Preserved registration retry/deadline/disconnect ownership, membership event ordering, token rotation, capacity rules, and the existing 64-member policy.
- Rechecked generation, sender identity, lobby mapping, and host authorization under the same lobby write lock before moderation mutations.
- Kept bounded sends, proxy/handshake limits, password lockout, cleanup ownership, and community-node validation intact.
- Pinned the Docker build to Rust 1.85 and `--locked`; no new install script, network endpoint, credential handling, or unsafe external behavior was added.

## Corrections and exclusions

- Excluded the PR's `.github` directory and ignore-file exceptions.
- Added a deterministic queued moderation test that changes the authenticated session while the lobby lock is contended; stale actions are rejected before mutation.
- Updated architecture/readme wording where it referred to CI that is intentionally excluded.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo +1.85.0 test --locked -- --test-threads=1`: 97 passed, 0 failed, 0 ignored.
- Local loopback WebSocket registration/moderation and the desktop/Android compatibility fixture passed.
- Docker image build was not run because Docker is unavailable on this workstation.
- No production server deployment was performed in this review.

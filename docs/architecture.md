# Signaling Server Architecture

The server remains one independently deployable Rust binary. Modules separate
ownership inside that binary; they do not change the WebSocket wire protocol.

## Connection Flow

1. `connection_guard` bounds pending handshakes, resolves trusted proxy sources,
   and acquires an active connection lease.
2. `connection` creates the sender and disconnect channel, sends the challenge,
   and enforces the registration deadline and message budget.
3. `protocol` validates message fields. The connection checks the current
   session and claimed sender before dispatching authenticated operations.
4. `registration` validates signed admission and returns explicit control flow.
   `moderation` handles host actions; the connection dispatches remaining
   routing, media, file-share, plaza, and community-node messages.
5. The connection owns normal exit and generation/sender-checked cleanup.

## Admission Ownership

`RegistrationRequest` contains wire values owned by one registration attempt.
`RegistrationContext` borrows connection dependencies; it does not own cleanup.

- `Retry` rejects the attempt before committing membership and permits another
  message on the same connection, subject to its original deadline.
- `Disconnect` rejects before membership commit. If a previously registered
  connection repeats registration, the connection retains its existing session.
- `Committed { session, disconnect }` always returns the new client id, lobby id,
  and generation, including when the session became stale immediately after
  commit. The connection stores all three before deciding whether to disconnect.
  Returning only `Disconnect` after a commit would lose cleanup ownership.

Keep identity verification, entry-mode/name admission, password checks, virtual
IP uniqueness, and capacity checks ahead of mutation. Membership replacement,
chat-token rotation, and reverse mapping update commit under the lobby write
lock. The configured lobby capacity permits replacement of an existing signed
identity; the existing absolute 64-member cap does not. Changing that policy is
a separate behavioral change, not part of module extraction.

## Lock And Event Rules

- When both shared maps are needed, acquire `lobbies` before
  `client_lobby_map`. Never wait for the lobby lock while retaining a map guard.
- Release shared state guards before socket I/O. Snapshot event recipients and
  data while locked, then use `transport` for bounded delivery.
- Current-session ownership includes client id, generation, and the exact
  sender `Arc`. An old socket must not delete or mutate its replacement.
- Moderation rechecks current-session ownership and host status under the same
  lobby write guard used for mutation. An earlier connection-level check alone
  is insufficient when another connection can replace the session.
- Admission notifications retain this sequence: registration success, member
  roster, token rotation to existing members, then player-joined broadcast.
- Kicking retains target disconnect, kicked/close delivery, player-left
  broadcast, then token rotation. Host transfer unmutes the new host before
  broadcasting host-changed.
- A dispatcher close result breaks to normal connection cleanup; it must not
  return from the connection handler before cleanup.

## Verification

Use the minimum supported toolchain when changing server code:

```bash
cargo +1.85.0 fmt --all -- --check
cargo +1.85.0 check --locked
cargo +1.85.0 test --locked
```

`registration` tests cover legacy rejection, invalid proofs, both capacity
policies, replacement, ordered membership events, and committed-but-disconnected
outcomes. `moderation` tests cover authorization, stale senders/generations,
membership cleanup, public/password constraints, limits, and event ordering.
Tests in `main` also exercise the complete WebSocket handler and cleanup paths.
Module tests use loopback sockets and in-memory lobby state, not deployed rooms.

## Remaining Boundaries

`connection` still dispatches the media, file-share, routing, and plaza domains.
Some older modules still import the parent namespace broadly. Extract the next
domain with explicit dependencies and direct tests before removing its original
branches. Keep message names, payload validation, authorization, deadlines,
quotas, and cleanup invariants unchanged unless a separate compatibility change
is intended.

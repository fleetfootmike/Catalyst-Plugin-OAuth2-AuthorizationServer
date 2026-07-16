# Refresh-token family revocation (RFC 9700 reuse detection)

Date: 2026-07-15
Dist: `Catalyst-Plugin-OAuth2-AuthorizationServer`
Status: designed, not implemented

## Problem

`refresh()` calls `store->rotate_refresh_token($hash)`, which atomically
validates-and-revokes the presented token and returns its binding. A stale
token replayed after rotation returns undef and the engine answers
`invalid_grant`. The currently-active refresh token in that family, and the
access tokens minted from it, stay alive.

RFC 9700 recommends revoking the whole family when reuse is detected: the
server cannot distinguish a legitimate client from an attacker replaying a
stolen token, and reuse is the strongest signal of theft an Authorization
Server gets. Raised by @piratefinn in the PR #1 review.

Two things block it today:

1. `rotate_refresh_token` collapses unknown, expired and already-revoked into a
   single undef, so a replay is indistinguishable from garbage. There is
   nothing to detect reuse with.
2. The binding carries `client_id`, `subject`, `scope` and `resource`. There is
   no family identity, so there is nothing to revoke even once detected.

## Decisions

Settled during brainstorming; recorded with the reasoning so they are not
relitigated:

- **Detection lives in `rotate_refresh_token`**, which grows a third outcome.
  Detection stays atomic and inside the call that already holds the row.
  Rejected: a second `find_refresh_family` lookup (non-atomic, extra
  round-trip on every bad token); the Store detecting and revoking internally
  (moves security policy out of the engine into every implementor).
- **Revoke the refresh family only.** Access tokens are stateless JWTs the
  Resource Server verifies without touching the Store, and they remain valid
  until `access_ttl` expires. Add a `jti` claim now so a denylist is possible
  later without a token-format change. Rejected: a `jti` denylist checked by
  the RS (makes the RS stateful, requires it to share the AS's Store, adds a
  round-trip per API call); no `jti` at all (no path to revocation later
  without breaking issued tokens).
- **Tombstones are retained until `expires_at`**, then the host may prune.
  The detection window equals `refresh_ttl`, which is exactly the window in
  which a stolen token is useful. Rejected: keeping tombstones forever
  (unbounded growth); a per-family row holding only the last-rotated hash
  (misses a replay from deeper in the chain).
- **Explicit `family_id` plus a `revoke_family` verb.** Rejected: chaining by
  parent hash (revocation becomes a traversal, every implementor must get
  chain-walking right); reusing `revoke_refresh_tokens_for_subject` (zero
  contract change and strictly safer, but one replay on a phone logs the user
  out of every device and client; RFC 9700 asks for the family, not the user).

## Store contract changes

Three changes to `Role::Store`. All three in-dist implementations
(`t/lib/StubStore.pm`, `t/lib/TestApp/Model/OAuthStore.pm`,
`examples/lib/Example/OAuthAS/Model/Store.pm`) must be updated. There are no
external implementors: the dist is pre-release and gobbyapi does not consume
it, so this is the moment to take the break.

### `rotate_refresh_token( $token_hash )`

Returns one of three outcomes instead of binding-or-undef:

| Outcome | Return | Engine does |
| --- | --- | --- |
| Valid | `{ binding => \%binding }` | Was live, now revoked; mint next pair |
| Unknown or expired | `undef` | Plain `invalid_grant` |
| Reused | `{ binding => .., reused => 1 }` | Revoke family, `invalid_grant` |

The binding is returned on the reuse path too: the engine needs `family_id`
off it to know what to revoke.

Wrapping in `{ binding => ... }` is the breaking part. The alternative, a
`$binding->{_reused}` flag, avoids the wrap but pollutes the binding namespace
with an engine concern. Take the break while it is free.

### `revoke_family( $family_id )` (new, required)

Revoke every refresh token sharing `$family_id`, live or tombstoned. Return
the count. Idempotent: revoking an already-revoked family is not an error.

### `create_refresh_token`'s binding gains `family_id`

Required and opaque. The Store must be able to find rows by it.

### Retention, stated in the role POD

A rotated row is retained until its original `expires_at`, revoked rather than
deleted. **Pruning earlier silently disables reuse detection**: the replay
degrades to undef, the engine reads it as unknown, and the family survives.
This belongs in the role POD where implementors read it, not only in
LIMITATIONS.

## Engine flow

### Family birth and inheritance

`_issue_token_pair` has two callers: the code exchange (line 279) and refresh
(line 296). The decision is made at the call sites, not inferred inside:

```perl
# exchange_authorization_code: a code exchange births a family
return $self->_issue_token_pair(
    { %$binding, family_id => $self->_random_token(16) } );

# refresh: the rotated binding already carries its family_id, inherit it
return $self->_issue_token_pair($binding);
```

`_issue_token_pair` asserts the invariant:

```perl
Carp::croak 'internal: _issue_token_pair requires a family_id'
    unless defined $binding->{family_id} && length $binding->{family_id};
```

**Why the assertion, and not a `//` fallback to a fresh token:**
the one-line inherit-or-birth is tempting, but if `family_id` ever failed to
propagate through a rotation it would silently birth a new family per
rotation. Every token becomes its own family, `revoke_family` revokes exactly
one token, and reuse detection appears to work while protecting nothing. Tests
would pass. The croak turns a silent security failure into a loud crash.

`_issue_token_pair` copies `family_id` into the binding it hands to
`create_refresh_token`, alongside the existing `client_id`, `subject`, `scope`
and `resource`.

### The reuse path in `refresh()`

```perl
my $result = $self->store->rotate_refresh_token( $self->_hash_token($raw) );
$self->_grant_error('unknown or revoked refresh token') unless $result;

if ( $result->{reused} ) {
    $self->store->revoke_family( $result->{binding}{family_id} );
    $self->_grant_error('refresh token reuse detected');
}
my $binding = $result->{binding};
```

Revoke before erroring, so the family dies even though the response is generic.

### `jti`

Added in `mint_access_token`'s fixed payload section, after `%$claims` so a
caller cannot override it:

```perl
jti => $self->_random_token(16),
```

Nothing reads it yet. It exists so a denylist is possible later without
changing the token format.

## Error semantics

- **Reuse returns a generic `invalid_grant`.** The response must not say
  "reuse detected": that confirms to an attacker that they hold a real token
  from a live family. `_grant_error` already yields `invalid_grant` and keeps
  the description off the wire, matching the dist's no-reflection style.
- **A `revoke_family` failure propagates as a 500.** It is not swallowed into
  `invalid_grant`. A Store that cannot revoke is broken, and answering
  `invalid_grant` while leaving a compromised family alive fails the wrong
  way. A 500 pages someone.

## Known consequence: concurrent refresh false positive

A concurrent double-refresh (same token, two in-flight requests, no attacker)
makes the loser look like a replay and revokes the family. This is RFC 9700's
own known false positive, and it is the price of detection: the difference
between a user retrying a flaky request and a user being logged out.

Document it as accepted. Store atomicity remains the mitigation, and the
existing concurrency note in the role POD is extended rather than replaced.

## AMENDMENT 2026-07-15: the above is not enough, and was wrong

The final whole-branch review found, and the controller reproduced, a race that
**inverts** the defence. The section above claims a concurrent double-refresh
revokes the family. It does not.

The engine makes two independent Store calls with nothing between them, so a
second request's `revoke_family` lands in the gap:

```text
R1: rotate_refresh_token(T)   -> live, tombstoned; about to create T'
R2: rotate_refresh_token(T)   -> reused -> revoke_family(F)
R1: create_refresh_token(T', family F)          <-- born AFTER the revoke
```

`revoke_family(F)` revokes what exists at that instant. `T'` does not exist
yet, so it is born **live into a revoked family**, and every later rotation
mints another live successor. Reproduced against StubStore with both Store
calls individually atomic, exactly as documented: 5 successful rotations after
the family was revoked, expected 0.

An attacker controls this race: fire two simultaneous refreshes with a stolen
token and retry until the loser's revoke lands in the winner's gap. The outcome
is worse than having no reuse detection: the legitimate client is locked out,
the attacker keeps the only live token, and the logs say the family was
revoked.

The role POD's "wrap both operations in a transaction" note cannot save a Store
author. The engine calls `rotate_refresh_token` and `create_refresh_token` as
two separate methods with no pairing or rollback contract, so no envelope is
possible across them. A Store implementing rotation as an autocommit
`UPDATE ... WHERE hash = ? AND revoked = 0` satisfies the documented contract
and is vulnerable.

### The fix: revocation is a property of the family, not of its rows

`revoke_family` must record **the family itself** as revoked, durably, rather
than only sweeping the rows that exist when it runs. `create_refresh_token`
must then refuse to birth a successor into a revoked family.

- `revoke_family( $family_id )`: mark the family revoked AND revoke its
  current tokens. Still returns the number newly revoked; still idempotent.
- `create_refresh_token( $token_hash, \%binding, $expires_at )`: if
  `$binding->{family_id}` names a revoked family, persist nothing and return
  false. Otherwise persist and return true.

The engine treats a false return as the family having died underneath it and
answers the same generic `invalid_grant`. R1 above now fails: correct, since
its family is compromised. Both parties are locked out, which is what RFC 9700
asks for.

**Why this works where the transaction note did not.** The check and the insert
live inside ONE Store method, so a Store can make them atomic by construction:
one statement, e.g. an `INSERT ... WHERE NOT EXISTS (SELECT 1 FROM
revoked_families WHERE family_id = ?)`. The previous design required atomicity
*across* two engine-called methods, which a Store cannot provide no matter how
carefully it is written. That is the difference between a contract an
implementer can satisfy and one they cannot.

### This also closes the single-flag problem

The review rated the single `revoked` flag an Important, not the harmless Minor
previously recorded, because it blocks this fix: to refuse a successor you must
ask "was this family revoked?", and with one flag that is unanswerable, since
every healthy chain has revoked rows (its own tombstones). The family-level
marker IS the missing distinction, so one change closes both.

### Cost

Another Store-contract break. Still free: pre-release, no external consumers.
The marker is per-family, so it is bounded by families rather than tokens, and
it is pruned on the same rule as tombstones (the host may remove it once the
family's tokens have expired).

## Documentation changes

- **`Role::Store` POD:** the three contract changes, and the retention rule
  with its silent-failure warning.
- **LIMITATIONS in `AuthorizationServer.pm`:** replace "family revocation on
  reuse is a planned enhancement" with what is now true. State plainly that
  reuse revokes the refresh family but does **not** kill already-minted access
  tokens, which stay valid until `access_ttl`. Note `jti` is present to enable
  a future denylist. Per the review, this is a SECURITY LIMITATION, not a
  planned enhancement.
- **Tombstone GC:** the host app's responsibility, alongside the existing DCR
  garbage-collection limitation, with the warning that pruning before
  `expires_at` disables detection.

## Testing

Behaviour, not implementation, since each of the three Stores is a place the
contract can be got wrong.

Tests that earn their keep:

- **A replay kills the live token.** Rotate to token N, replay N-1, then try
  to refresh with N. N must fail. This is the entire feature: if only the
  replayed token dies, nothing was built. Fails against today's code and
  against the silent per-rotation-family bug.
- **Cross-family isolation, same subject.** Two families for one user (two
  devices). Replay in family A. Family B still refreshes. This is what
  separates the chosen design from the rejected subject-wide revocation:
  without it, a `revoke_family` that lazily calls
  `revoke_refresh_tokens_for_subject` passes everything else.
- **`family_id` survives a chain of rotations.** Rotate three or four deep,
  assert one family throughout.
- **Deep replay.** Replay token N-3, not just N-1: pins that retention covers
  the whole chain, not only the most recent hop.
- **Unknown token revokes nothing.** Garbage yields `invalid_grant` with no
  `revoke_family` call. Guards against revoking on every bad token.
- **The `family_id` invariant croaks** when `_issue_token_pair` gets a binding
  without one.
- **`jti` present and unique** across two mints.
- **`revoke_family` is idempotent.**

Characterisation tests, pinning decisions rather than fixing bugs:

- The reuse error is byte-identical to the unknown-token error (no oracle).
- A tombstone is present-but-revoked before `expires_at`.

**Mutation-check the replay-kills-live-token test:** make `revoke_family` a
no-op and confirm it fails. A test that passes against a do-nothing
implementation is worse than none, and this feature is exactly the shape where
that happens.

## Out of scope

- An RFC 7009 revocation endpoint.
- A `jti` denylist, or any Resource Server change. The RS stays stateless.
- Asymmetric signing.

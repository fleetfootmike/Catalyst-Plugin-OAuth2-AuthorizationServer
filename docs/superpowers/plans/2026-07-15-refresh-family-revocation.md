# Refresh-Token Family Revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect refresh-token reuse and revoke the whole token family, per
RFC 9700, as asked for in @piratefinn's PR #1 review.

**Architecture:** `rotate_refresh_token` grows a third outcome so a replay is
distinguishable from garbage, which means rotated rows become tombstones
rather than being deleted. Each refresh chain carries an opaque `family_id`
born at the code exchange and inherited through every rotation. On a detected
replay the engine calls a new `revoke_family` Store verb, then answers a
generic `invalid_grant`.

**Tech Stack:** Perl 5.36, Moo, Catalyst, Crypt::JWT, Test::More, Test::Fatal.

**Spec:** `docs/superpowers/specs/`
`2026-07-15-refresh-family-revocation-design.md`

## Global Constraints

- **Do not commit without asking.** Each task ends with a proposed commit
  message; surface the diff and ask the user for an explicit OK first. This
  overrides the plan's own "Commit" steps.
- **ASCII only.** No em dashes, no smart quotes, no non-ASCII in code,
  comments, POD, tests or docs. Verify with
  `grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .`
  which must return nothing.
- **Style:** 4-space soft tabs, no hard tabs, no trailing whitespace, newline
  at EOF. `use v5.36` signatures. Match surrounding code.
- **Tests:** `prove -lr t` green. `PERL_CRITIC_TEST=1 prove -l t/perl_critic.t`
  green (severity 3, see `.perlcriticrc`). Test::More, not Test2.
- **MANIFEST lists every `t/` file.** A new test file MUST be hand-added to
  MANIFEST or it vanishes from `make dist`. Do NOT run `make manifest`: it
  regenerates and reorders the file. Hand-add the line.
- **Three Store implementations** must stay in sync with the role:
  `t/lib/StubStore.pm`, `t/lib/TestApp/Model/OAuthStore.pm`,
  `examples/lib/Example/OAuthAS/Model/Store.pm`.
- **No external consumers.** The dist is pre-release and gobbyapi does not use
  it, so breaking the Store contract is free. Take the break cleanly.

## File Structure

| File | Responsibility | Tasks |
| --- | --- | --- |
| `lib/.../Role/Store.pm` | Storage contract + POD | 1, 2, 3 |
| `lib/.../Server.pm` | Engine: detection policy, family, jti | 1, 2, 3, 4 |
| `lib/.../AuthorizationServer.pm` | LIMITATIONS POD | 3, 4 |
| `t/lib/StubStore.pm` | Unit-test Store | 1, 2, 3 |
| `t/lib/TestApp/Model/OAuthStore.pm` | Catalyst-app-test Store | 1, 2, 3 |
| `examples/lib/Example/OAuthAS/Model/Store.pm` | Example Store | 1, 2, 3 |
| `t/server-refresh-family.t` | New: all family/reuse behaviour | 1, 2, 3 |
| `t/server-token-mint.t` | jti claim | 4 |
| `MANIFEST` | Add the new test file | 1 |

---

### Task 1: rotate_refresh_token returns a three-way outcome

Detection without policy. After this task a replay is *distinguishable* but
the family is not yet revoked: externally the behaviour is unchanged
(`invalid_grant` either way). That is deliberate, and it keeps this task
independently reviewable.

**Files:**

- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Role/Store.pm`
- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Server.pm` (`refresh`)
- Modify: `t/lib/StubStore.pm`
- Modify: `t/lib/TestApp/Model/OAuthStore.pm`
- Modify: `examples/lib/Example/OAuthAS/Model/Store.pm`
- Create: `t/server-refresh-family.t`
- Modify: `MANIFEST`

**Interfaces:**

- Produces: `rotate_refresh_token($hash)` returns `undef` |
  `{ binding => \%binding }` | `{ binding => \%binding, reused => 1 }`.
  Task 3 consumes the `reused` flag.

- [ ] **Step 1: Write the failing test**

Create `t/server-refresh-family.t`:

```perl
use v5.36;
use Test::More;
use Test::Fatal;
use lib 't/lib';
use StubStore;

my $class = 'Catalyst::Plugin::OAuth2::AuthorizationServer::Server';
require_ok($class);

# A live token rotates once, then reports reuse on replay.
{
    my $store = StubStore->new;
    $store->create_refresh_token( 'h1',
        { client_id => 'c1', subject => 'user-9' }, time + 3600 );

    my $first = $store->rotate_refresh_token('h1');
    is( ref $first, 'HASH', 'rotate returns a hashref' );
    is( $first->{binding}{subject}, 'user-9', 'binding comes back wrapped' );
    ok( !$first->{reused}, 'a live token is not flagged as reused' );

    my $replay = $store->rotate_refresh_token('h1');
    ok( $replay,            'a replayed token is not undef' );
    ok( $replay->{reused},  'a replayed token is flagged reused' );
    is( $replay->{binding}{subject}, 'user-9',
        'the replay carries the binding so the family can be found' );
}

# Unknown and expired stay undef: they are not replays.
{
    my $store = StubStore->new;
    is( $store->rotate_refresh_token('nope'), undef, 'unknown token -> undef' );

    $store->create_refresh_token( 'old', { subject => 'u' }, time - 1 );
    is( $store->rotate_refresh_token('old'), undef, 'expired token -> undef' );
}

done_testing;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `prove -l t/server-refresh-family.t`
Expected: FAIL. `rotate` currently returns the bare binding, so
`$first->{binding}{subject}` is undef and the replay returns undef (the row
was deleted).

- [ ] **Step 3: Tombstone in all three Stores**

`t/lib/StubStore.pm`, replacing `create_refresh_token` and
`rotate_refresh_token`:

```perl
sub create_refresh_token ( $self, $hash, $binding, $exp ) {
    $self->refresh->{$hash}
        = { binding => $binding, exp => $exp, revoked => 0 };
    return 1;
}
sub rotate_refresh_token ( $self, $hash ) {
    my $row = $self->refresh->{$hash} or return undef;
    return undef if $row->{exp} < time;
    return { binding => $row->{binding}, reused => 1 } if $row->{revoked};
    $row->{revoked} = 1;    # tombstone: retained until exp, never deleted
    return { binding => $row->{binding} };
}
```

`revoke_refresh_tokens_for_subject` in the same file must stop deleting, so
tombstones survive:

```perl
sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %{ $self->refresh } ) {
        my $row = $self->refresh->{$h};
        next if $row->{revoked};
        next unless ( $row->{binding}{subject} // '' ) eq $subject;
        $row->{revoked} = 1;
        $n++;
    }
    return $n;
}
```

`t/lib/TestApp/Model/OAuthStore.pm` (note this file names the binding key `b`):

```perl
sub create_refresh_token ( $self, $hash, $b, $exp ) {
    $REFRESH{$hash} = { b => $b, exp => $exp, revoked => 0 }; return 1;
}
sub rotate_refresh_token ( $self, $hash ) {
    my $row = $REFRESH{$hash} or return undef;
    return undef if $row->{exp} < time;
    return { binding => $row->{b}, reused => 1 } if $row->{revoked};
    $row->{revoked} = 1;
    return { binding => $row->{b} };
}
sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{subject} // '' ) eq $subject;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}
```

`examples/lib/Example/OAuthAS/Model/Store.pm` (same `b` key, same three subs):

```perl
sub create_refresh_token ( $self, $hash, $binding, $exp ) {
    $REFRESH{$hash} = { b => $binding, exp => $exp, revoked => 0 };
    return 1;
}

sub rotate_refresh_token ( $self, $hash ) {
    my $row = $REFRESH{$hash} or return undef;
    return undef if $row->{exp} < time;
    return { binding => $row->{b}, reused => 1 } if $row->{revoked};
    $row->{revoked} = 1;
    return { binding => $row->{b} };
}

sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{subject} // '' ) eq $subject;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}
```

- [ ] **Step 4: Teach the engine to unwrap**

In `lib/.../Server.pm`, `sub refresh`, replace the first two lines of the body
after the `$raw` check:

```perl
    my $result = $self->store->rotate_refresh_token( $self->_hash_token($raw) );
    $self->_grant_error('unknown or revoked refresh token') unless $result;

    # A replayed token is detected here but the family is not revoked until
    # Task 3 wires revoke_family in. Same generic error either way.
    $self->_grant_error('unknown or revoked refresh token')
        if $result->{reused};

    my $binding = $result->{binding};
```

- [ ] **Step 5: Run the new test and the full suite**

Run: `prove -l t/server-refresh-family.t && prove -lr t`
Expected: both PASS. `t/server-token.t`'s existing rotation test must still
pass unchanged: it asserts a rotation issues a new pair, which is unaffected.

- [ ] **Step 6: Document the contract in the role POD**

In `lib/.../Role/Store.pm`, replace the `rotate_refresh_token` entry:

```pod
=head2 rotate_refresh_token( $token_hash )

Atomically validate-and-revoke the refresh token identified by C<$token_hash>.
Returns one of three outcomes:

=over

=item C<undef>

Unknown or expired. Not a replay: the engine answers C<invalid_grant> and does
nothing else.

=item C<< { binding => \%binding } >>

The token was live and is now revoked. The engine mints the next pair.

=item C<< { binding => \%binding, reused => 1 } >>

The token is known but was already revoked: a replay. The binding is returned
so the engine can read C<family_id> off it and revoke the family.

=back

B<Retention:> a rotated token MUST be retained until its original
C<$expires_at>, marked revoked rather than deleted. Pruning earlier silently
disables reuse detection: the replay degrades to C<undef>, the engine reads it
as unknown, and the compromised family survives. Pruning after C<$expires_at>
is the host application's job.

B<Concurrency note:> a non-atomic implementation enables refresh-token replay
under concurrent requests. The engine calls C<create_refresh_token> immediately
after C<rotate_refresh_token> with no transactional envelope: a crash between
the two calls will invalidate the session. Wrap both operations in a
transaction if the backend supports it.
```

- [ ] **Step 7: Add the new test to MANIFEST**

Hand-add this line to `MANIFEST`, in alphabetical position among the `t/`
entries (after `t/server-metadata.t`):

```text
t/server-refresh-family.t
```

Do NOT run `make manifest`.

- [ ] **Step 8: Verify everything**

```bash
prove -lr t
PERL_CRITIC_TEST=1 prove -l t/perl_critic.t
grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .
git diff --check
```

Expected: suite PASS, critic PASS, grep silent, `--check` silent.

- [ ] **Step 9: Ask before committing, then commit**

Proposed message:

```text
Make a replayed refresh token distinguishable from garbage

rotate_refresh_token collapsed unknown, expired and already-revoked into one
undef, so a replay looked exactly like a bad token and there was nothing to
detect reuse with. It now returns a third outcome, which means rotated rows
have to be kept as tombstones until they expire rather than deleted.

No behaviour change yet: a replay still answers invalid_grant. Revoking the
family comes next.
```

---

### Task 2: family_id, born at the code exchange, inherited on rotation

**Files:**

- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Server.pm`
- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Role/Store.pm` (POD)
- Modify: `t/server-refresh-family.t`

**Interfaces:**

- Consumes: Task 1's wrapped `rotate_refresh_token` outcome.
- Produces: every refresh binding carries `family_id` (opaque string). Task 3
  reads `$result->{binding}{family_id}`.

- [ ] **Step 1: Write the failing test**

Append to `t/server-refresh-family.t`, before `done_testing`. This needs the
PKCE helpers, so add these `use` lines at the top of the file alongside the
existing ones:

```perl
use Digest::SHA qw/sha256/;
use MIME::Base64 qw/encode_base64url/;
```

and these helpers after `require_ok($class)`:

```perl
my $key      = 'k' x 32;
my $VERIFIER = 'pkce-verifier-' . ( '0' x 29 );

sub fresh_engine { return $class->new(
    store => StubStore->new, signing_key => $key,
    issuer => 'https://as', resource => 'https://rs/mcp',
) }

sub mint_code ( $eng, $verifier, $subject = 'user-9' ) {
    my $challenge = encode_base64url( sha256($verifier) );
    $eng->store->create_client({
        client_id => 'c1', redirect_uris => ['https://app/cb'] });
    my $rid = $eng->validate_authorize({
        client_id => 'c1', redirect_uri => 'https://app/cb',
        response_type => 'code', code_challenge => $challenge,
        code_challenge_method => 'S256', scope => 'gobby:read',
        resource => 'https://rs/mcp',
    })->{request_id};
    return $eng->issue_code( $subject, $rid )->{code};
}

sub first_pair ( $eng, $verifier = $VERIFIER, $subject = 'user-9' ) {
    my $code = mint_code( $eng, $verifier, $subject );
    return $eng->exchange_authorization_code({
        grant_type => 'authorization_code', code => $code,
        redirect_uri => 'https://app/cb', code_verifier => $verifier,
    });
}

# refresh, returning the new pair
sub do_refresh ( $eng, $rt ) {
    return $eng->refresh(
        { grant_type => 'refresh_token', refresh_token => $rt } );
}

# refresh, returning the exception (undef when it succeeded)
sub try_refresh ( $eng, $rt ) {
    return exception { do_refresh( $eng, $rt ) };
}

# every stored binding, newest first, for assertions about family identity
sub bindings ( $eng ) {
    my $r = $eng->store->refresh;
    return [ map { $r->{$_}{binding} } keys %$r ];
}
```

The test itself:

```perl
# family_id is born at the code exchange and survives a chain of rotations
{
    my $eng  = fresh_engine();
    my $pair = first_pair($eng);

    my ($born) = map { $_->{family_id} } @{ bindings($eng) };
    ok( defined $born && length $born, 'code exchange births a family_id' );

    my $rt = $pair->{refresh_token};
    for my $hop ( 1 .. 3 ) {
        my $next = $eng->refresh({
            grant_type => 'refresh_token', refresh_token => $rt });
        $rt = $next->{refresh_token};
    }

    my %families = map { ( $_->{family_id} // 'MISSING' ) => 1 }
        @{ bindings($eng) };
    is( scalar keys %families, 1,
        'one family_id across the whole rotation chain' );
    is( ( keys %families )[0], $born, 'and it is the family born at exchange' );
}

# the invariant: _issue_token_pair refuses a binding with no family_id
{
    my $eng = fresh_engine();
    my $no_family = { client_id => 'c1', subject => 'u' };
    like(
        exception { $eng->_issue_token_pair($no_family) },
        qr/family_id/,
        '_issue_token_pair croaks without a family_id'
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `prove -l t/server-refresh-family.t`
Expected: FAIL. `family_id` is undef everywhere, so the born assertion fails
and `_issue_token_pair` does not croak.

- [ ] **Step 3: Implement birth, inheritance and the invariant**

In `lib/.../Server.pm`, `sub _issue_token_pair`, add the assertion as the
first statement and carry `family_id` into the stored binding:

```perl
sub _issue_token_pair ( $self, $binding ) {
    # Birth is the caller's job (see exchange_authorization_code); inheritance
    # is the rotated binding's. Defaulting here with // would silently birth a
    # new family per rotation, so revoke_family would revoke exactly one token
    # and detection would look like it works while protecting nothing.
    Carp::croak 'internal: _issue_token_pair requires a family_id'
        unless defined $binding->{family_id} && length $binding->{family_id};

    my $access = $self->mint_access_token(
        {
            sub => $binding->{subject},
            ( defined $binding->{scope} ? ( scope => $binding->{scope} ) : () ),
        },
        $binding->{resource},
    );
    my $refresh = $self->_random_token(32);
    $self->store->create_refresh_token(
        $self->_hash_token($refresh),
        {
            client_id => $binding->{client_id},
            subject   => $binding->{subject},
            scope     => $binding->{scope},
            resource  => $binding->{resource},
            family_id => $binding->{family_id},
        },
        $self->_now + $self->refresh_ttl,
    );
    return {
        access_token  => $access,
        token_type    => 'Bearer',
        expires_in    => $self->access_ttl,
        refresh_token => $refresh,
        ( defined $binding->{scope} ? ( scope => $binding->{scope} ) : () ),
    };
}
```

At the end of `sub exchange_authorization_code`, replace
`return $self->_issue_token_pair($binding);` with:

```perl
    # A code exchange births a new family; a rotation inherits one.
    return $self->_issue_token_pair(
        { %$binding, family_id => $self->_random_token(16) } );
```

Leave `sub refresh`'s `return $self->_issue_token_pair($binding);` alone: the
rotated binding already carries the family.

- [ ] **Step 4: Run the new test and the full suite**

Run: `prove -l t/server-refresh-family.t && prove -lr t`
Expected: both PASS.

- [ ] **Step 5: Document family_id in the role POD**

In `lib/.../Role/Store.pm`, replace the `create_refresh_token` entry:

```pod
=head2 create_refresh_token( $token_hash, \%binding, $expires_at )

Persist a refresh token by its hash (never the raw token). C<\%binding> carries
C<client_id>, C<subject>, C<scope>, C<resource> and C<family_id>. Return true.

C<family_id> is an opaque string identifying the rotation chain this token
belongs to: it is minted when an authorization code is exchanged and inherited
by every token rotated from it. The Store MUST persist it and MUST be able to
find rows by it (see C<revoke_family>).
```

- [ ] **Step 6: Verify everything**

```bash
prove -lr t
PERL_CRITIC_TEST=1 prove -l t/perl_critic.t
grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .
```

Expected: suite PASS, critic PASS, grep silent.

- [ ] **Step 7: Ask before committing, then commit**

Proposed message:

```text
Give every refresh chain a family identity

A code exchange births a family_id and each rotation inherits it, so the tokens
descended from one authorization now have something in common to revoke.

_issue_token_pair asserts the family_id rather than defaulting it. The one-line
// fallback is tempting and wrong: if propagation ever broke, every token would
become its own family, revocation would revoke one token, and the tests would
still pass.
```

---

### Task 3: revoke_family, and wiring the reuse path

The payoff. This is the task where the feature either works or silently does
nothing, so the tests matter more than the code.

**Files:**

- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Role/Store.pm`
- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Server.pm` (`refresh`)
- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer.pm` (LIMITATIONS)
- Modify: `t/lib/StubStore.pm`
- Modify: `t/lib/TestApp/Model/OAuthStore.pm`
- Modify: `examples/lib/Example/OAuthAS/Model/Store.pm`
- Modify: `t/server-refresh-family.t`
- Modify: `t/role-store.t` (the role's required-verb list)

**Interfaces:**

- Consumes: Task 1's `reused` flag, Task 2's `family_id`.
- Produces: `revoke_family($family_id)` returns the count newly revoked.

- [ ] **Step 1: Write the failing tests**

Append to `t/server-refresh-family.t`, before `done_testing`:

```perl
# THE test: a replay kills the live token, not just the replayed one
{
    my $eng   = fresh_engine();
    my $pair  = first_pair($eng);
    my $stale = $pair->{refresh_token};
    my $live  = do_refresh( $eng, $stale )->{refresh_token};

    # attacker replays the stale token
    isnt( try_refresh( $eng, $stale ), undef,
        'replaying the stale token is rejected' );

    # the legitimate client's live token must now be dead too
    isnt( try_refresh( $eng, $live ), undef,
        'the live token is revoked by the replay (family revoked)' );
}

# cross-family isolation: one user, two devices, one replay
{
    my $eng = fresh_engine();
    my $a   = first_pair( $eng, $VERIFIER, 'user-9' );
    my $b   = first_pair( $eng, 'other-verifier-' . ( '1' x 28 ), 'user-9' );

    my $a_stale = $a->{refresh_token};
    do_refresh( $eng, $a_stale );

    isnt( try_refresh( $eng, $a_stale ), undef,
        'replay in family A is rejected' );

    # family B belongs to the same subject and must be untouched
    is( try_refresh( $eng, $b->{refresh_token} ), undef,
        'family B still refreshes: per-family, not per-subject' );
}

# a replay from deeper in the chain still kills the family
{
    my $eng  = fresh_engine();
    my $deep = first_pair($eng)->{refresh_token};

    my $rt = $deep;
    $rt = do_refresh( $eng, $rt )->{refresh_token} for 1 .. 3;

    isnt( try_refresh( $eng, $deep ), undef,
        'replaying a token from 3 hops back is rejected' );
    isnt( try_refresh( $eng, $rt ), undef,
        'and it revokes the family, killing the current token' );
}

# an unknown token revokes nothing
{
    my $eng  = fresh_engine();
    my $pair = first_pair($eng);

    my $revoked = 0;
    no warnings 'redefine';
    my $orig = \&StubStore::revoke_family;
    local *StubStore::revoke_family = sub { $revoked++; $orig->(@_) };

    isnt( try_refresh( $eng, 'garbage' ), undef,
        'an unknown refresh token is rejected' );
    is( $revoked, 0, 'an unknown token revokes no family' );

    is( try_refresh( $eng, $pair->{refresh_token} ), undef,
        'and the real token still works' );
}

# no oracle: reuse and unknown are indistinguishable to the client
{
    my $eng   = fresh_engine();
    my $stale = first_pair($eng)->{refresh_token};
    do_refresh( $eng, $stale );

    my $reuse   = try_refresh( $eng, $stale );
    my $unknown = try_refresh( $eng, 'garbage' );

    is( $reuse->error, $unknown->error,
        'reuse and unknown share an error code' );
    is( $reuse->error_description, $unknown->error_description,
        'and a description: no reuse oracle for an attacker' );
}

# revoke_family is idempotent
{
    my $eng  = fresh_engine();
    first_pair($eng);
    my ($fid) = map { $_->{family_id} } @{ bindings($eng) };

    my $first = $eng->store->revoke_family($fid);
    is( $first, 1, 'revoking a one-token family revokes one token' );
    is( $eng->store->revoke_family($fid), 0,
        'revoking again is a no-op, not an error' );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `prove -l t/server-refresh-family.t`
Expected: FAIL with `Can't locate object method "revoke_family"`, and the
replay-kills-live-token test failing because the live token still refreshes.

- [ ] **Step 3: Add revoke_family to the role**

In `lib/.../Role/Store.pm`, add to the `requires` list (after
`rotate_refresh_token`):

```perl
    revoke_family
```

and add the POD entry after `rotate_refresh_token`'s:

```pod
=head2 revoke_family( $family_id )

Revoke every refresh token sharing C<$family_id>, live or already tombstoned.
Return the number newly revoked. Idempotent: revoking an already-revoked
family returns 0 and is not an error.

Called when C<rotate_refresh_token> reports a replay. Revoking the family is
the only defence the server has against a stolen refresh token, because it
cannot tell the legitimate client from the attacker.
```

- [ ] **Step 4: Implement revoke_family in all three Stores**

`t/lib/StubStore.pm`:

```perl
sub revoke_family ( $self, $family_id ) {
    my $n = 0;
    for my $h ( keys %{ $self->refresh } ) {
        my $row = $self->refresh->{$h};
        next if $row->{revoked};
        next unless ( $row->{binding}{family_id} // '' ) eq $family_id;
        $row->{revoked} = 1;
        $n++;
    }
    return $n;
}
```

`t/lib/TestApp/Model/OAuthStore.pm`:

```perl
sub revoke_family ( $self, $family_id ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{family_id} // '' ) eq $family_id;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}
```

`examples/lib/Example/OAuthAS/Model/Store.pm`:

```perl
sub revoke_family ( $self, $family_id ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{family_id} // '' ) eq $family_id;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}
```

- [ ] **Step 5: Wire the reuse path in the engine**

In `lib/.../Server.pm`, `sub refresh`, replace the Task 1 placeholder block:

```perl
    my $result = $self->store->rotate_refresh_token( $self->_hash_token($raw) );
    $self->_grant_error('unknown or revoked refresh token') unless $result;

    # RFC 9700: a replay means the chain is compromised and we cannot tell the
    # legitimate client from the attacker, so the whole family goes. Revoke
    # before erroring, and let a failing revoke_family surface as a 500: a
    # Store that cannot revoke is broken, and answering invalid_grant while
    # leaving the family alive fails the wrong way.
    if ( $result->{reused} ) {
        $self->store->revoke_family( $result->{binding}{family_id} );
        # Same error and description as an unknown token: telling an attacker
        # that reuse was detected confirms they hold a real token.
        $self->_grant_error('unknown or revoked refresh token');
    }

    my $binding = $result->{binding};
```

- [ ] **Step 6: Update the role's required-verb test**

`t/role-store.t` asserts the required verbs. Add `revoke_family` to the list it
checks. Read the file first and follow its existing shape.

- [ ] **Step 7: Run tests to verify they pass**

Run: `prove -l t/server-refresh-family.t && prove -lr t`
Expected: both PASS.

- [ ] **Step 8: Mutation-check the headline test**

This feature's failure mode is looking like it works. Prove the key test bites:

```bash
cp t/lib/StubStore.pm /tmp/StubStore.bak
# make revoke_family a no-op
perl -pi -e 's/^(sub revoke_family.*\{)$/$1 return 0;/' t/lib/StubStore.pm
prove -l t/server-refresh-family.t   # MUST FAIL
cp /tmp/StubStore.bak t/lib/StubStore.pm
prove -l t/server-refresh-family.t   # MUST PASS
```

Expected: FAIL then PASS. If the no-op `revoke_family` passes, the test is
worthless: fix it before continuing.

- [ ] **Step 9: Rewrite LIMITATIONS**

In `lib/.../AuthorizationServer.pm`, replace the first LIMITATIONS paragraph:

```pod
=head1 LIMITATIONS

Refresh-token reuse revokes the whole token family (RFC 9700): when a rotated
token is replayed, every refresh token descended from the same authorization
is revoked, including the one the legitimate client currently holds. Reuse
detection depends on the Store retaining rotated tokens until they expire; see
C<rotate_refresh_token> in
L<Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store>.

B<Security limitation:> revoking the family does B<not> kill access tokens
already minted from it. They are stateless JWTs, verified without consulting
the Store, and stay valid until C<access_ttl> elapses. Keep C<access_ttl>
short. Access tokens carry a C<jti> claim so a denylist can be added later
without changing the token format, but this plugin implements no denylist and
no RFC 7009 revocation endpoint.

A concurrent double-refresh (the same token presented twice at once, with no
attacker involved) is indistinguishable from a replay and will revoke the
family. This is inherent to RFC 9700 reuse detection.

Pruning revoked refresh tokens after they expire is the host application's
responsibility, as is garbage-collecting abandoned Dynamic Client
Registrations (clients that never completed a token exchange): the Store has
the visibility to identify and remove them. This plugin tracks no client
usage.
```

- [ ] **Step 10: Verify everything**

```bash
prove -lr t
PERL_CRITIC_TEST=1 prove -l t/perl_critic.t
grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .
plackup examples/app.psgi &   # then, in another shell:
perl examples/client.pl       # must complete the full flow, exit 0
```

Expected: suite PASS, critic PASS, grep silent, example client exits 0.

- [ ] **Step 11: Ask before committing, then commit**

Proposed message:

```text
Revoke the whole refresh family when a token is replayed

RFC 9700: a replayed refresh token means the chain is compromised, and the
server cannot tell the legitimate client from the attacker, so every token
descended from the same authorization goes. The client holding the live token
gets logged out, which is the point.

The error stays byte-identical to an unknown token. Saying "reuse detected"
would confirm to an attacker that they hold a real token from a live family.

A failing revoke_family surfaces as a 500 rather than being swallowed into
invalid_grant: a Store that cannot revoke is broken, and answering
invalid_grant while the compromised family lives on fails the wrong way.

LIMITATIONS now says plainly that this does not kill already-minted access
tokens, instead of calling family revocation a planned enhancement.
```

---

### Task 4: jti claim on access tokens

**Files:**

- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Server.pm`
  (`mint_access_token`)
- Modify: `t/server-token-mint.t`

**Interfaces:**

- Produces: every access token carries a unique `jti` claim. Nothing reads it.

- [ ] **Step 1: Write the failing test**

Append to `t/server-token-mint.t`, before `done_testing`:

```perl
# jti: present, unique per mint, and not overridable by the caller
{
    my $eng = $class->new(
        store => StubStore->new, signing_key => $key,
        issuer => 'https://as', resource => 'https://rs/mcp',
    );
    my $one = decode_jwt(
        token => $eng->mint_access_token({ sub => 'u' }), key => $key );
    my $two = decode_jwt(
        token => $eng->mint_access_token({ sub => 'u' }), key => $key );

    ok( length $one->{jti}, 'access token carries a jti' );
    isnt( $one->{jti}, $two->{jti}, 'jti is unique per mint' );

    my $forced = decode_jwt(
        token => $eng->mint_access_token({ sub => 'u', jti => 'attacker' }),
        key   => $key );
    isnt( $forced->{jti}, 'attacker', 'a caller cannot pin the jti' );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `prove -l t/server-token-mint.t`
Expected: FAIL. `jti` is undef, so the length check fails.

- [ ] **Step 3: Add jti to the fixed payload**

In `lib/.../Server.pm`, `sub mint_access_token`, add `jti` to `%payload` after
`%$claims` so a caller cannot override it:

```perl
    my %payload = (
        %$claims,
        iss => $self->issuer,
        aud => ( @aud == 1 ? $aud[0] : \@aud ),
        iat => $now,
        exp => $now + $self->access_ttl,
        # Nothing reads jti yet. It exists so a revocation denylist can be
        # added later without changing the token format for issued tokens.
        jti => $self->_random_token(16),
    );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `prove -l t/server-token-mint.t && prove -lr t`
Expected: both PASS.

- [ ] **Step 5: Verify everything**

```bash
prove -lr t
PERL_CRITIC_TEST=1 prove -l t/perl_critic.t
grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .
```

Expected: suite PASS, critic PASS, grep silent.

- [ ] **Step 6: Ask before committing, then commit**

Proposed message:

```text
Stamp a jti on access tokens

Nothing reads it. It is here so a revocation denylist becomes possible later
without changing the token format for tokens already issued, which is the part
that would otherwise be a breaking change.

It goes in the fixed half of the payload, after the caller's claims, so a
caller cannot pin it to a value of their choosing.
```

---

### Task 5: close the concurrent-replay race (added 2026-07-15)

Tasks 1-4 are committed. The final whole-branch review found, and the
controller reproduced, a race that inverts the whole defence. See the spec's
`AMENDMENT 2026-07-15` section.

The engine makes two independent Store calls with nothing between them:

```text
R1: rotate_refresh_token(T)   -> live, tombstoned; about to create T'
R2: rotate_refresh_token(T)   -> reused -> revoke_family(F)
R1: create_refresh_token(T', family F)          <-- born AFTER the revoke
```

`T'` is born live into a revoked family and rotates indefinitely. Reproduced:
5 successful rotations after revocation, expected 0. The attacker controls the
timing and can retry until it lands, ending with the only live token in a
family the logs say was revoked.

**Fix:** make revocation a property of the family, not of the rows that happen
to exist. `revoke_family` marks the family; `create_refresh_token` refuses to
birth into a marked family. Both live in ONE Store method each, so a Store can
be atomic by construction, which the previous "wrap both in a transaction"
note could never deliver across two engine-called methods.

**Files:**

- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Role/Store.pm`
- Modify: `lib/Catalyst/Plugin/OAuth2/AuthorizationServer/Server.pm`
- Modify: `t/lib/StubStore.pm`
- Modify: `t/lib/TestApp/Model/OAuthStore.pm`
- Modify: `examples/lib/Example/OAuthAS/Model/Store.pm`
- Modify: `t/server-refresh-family.t`

**Interfaces:**

- Consumes: Task 3's `revoke_family($family_id)`, Task 2's `family_id`.
- Produces: `create_refresh_token` returns false when the family is revoked.

- [ ] **Step 1: Write the failing test**

This is the reproduction, and it must fail before the fix. Append to
`t/server-refresh-family.t`. It drives the replay from inside the winner's
`create_refresh_token`, which is the only way to hit the gap deterministically:

```perl
# A replay racing a rotation must not leave a live token in the dead family.
{
    my $eng   = fresh_engine();
    my $stale = first_pair($eng)->{refresh_token};

    my $interleaved = 0;
    no warnings 'redefine';
    my $orig = \&StubStore::create_refresh_token;
    local *StubStore::create_refresh_token = sub {
        my @args = @_;
        # R2 lands in R1's gap: after R1 rotated, before R1 created.
        eval { do_refresh( $eng, $stale ) } unless $interleaved++;
        return $orig->(@args);
    };

    my $r1 = eval { do_refresh( $eng, $stale ) };
    ok( $interleaved, 'the replay interleaved' );

    my $rt = $r1 && $r1->{refresh_token};
    my $survived = 0;
    if ($rt) {
        for ( 1 .. 5 ) {
            my $next = eval { do_refresh( $eng, $rt ) } or last;
            $rt = $next->{refresh_token};
            $survived++;
        }
    }
    is( $survived, 0, 'no rotation survives a raced family revocation' );
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `prove -l t/server-refresh-family.t`
Expected: FAIL, `got: '5'  expected: '0'`. If it does not fail, the
reproduction is wrong: fix it before changing any code.

- [ ] **Step 3: Add the family marker to the three Stores**

Each Store gains a revoked-families record and two behaviour changes:
`revoke_family` marks the family; `create_refresh_token` refuses a marked one.

`t/lib/StubStore.pm` (per-instance storage, binding key `binding`):

```perl
has revoked_families => ( is => 'ro', default => sub { {} } );

sub create_refresh_token ( $self, $hash, $binding, $exp ) {
    # A successor must not be born into a family that has been revoked. The
    # check and the insert are one Store call, so this is atomic by
    # construction; the engine cannot provide that across two calls.
    return 0 if $self->revoked_families->{ $binding->{family_id} // '' };
    $self->refresh->{$hash}
        = { binding => $binding, exp => $exp, revoked => 0 };
    return 1;
}

sub revoke_family ( $self, $family_id ) {
    # Mark the FAMILY, not just the rows that exist right now: a rotation in
    # flight may still create a successor after this returns.
    $self->revoked_families->{$family_id} = 1;
    my $n = 0;
    for my $h ( keys %{ $self->refresh } ) {
        my $row = $self->refresh->{$h};
        next if $row->{revoked};
        next unless ( $row->{binding}{family_id} // '' ) eq $family_id;
        $row->{revoked} = 1;
        $n++;
    }
    return $n;
}
```

`t/lib/TestApp/Model/OAuthStore.pm` and
`examples/lib/Example/OAuthAS/Model/Store.pm` both use a process-wide hash and
the binding key `b`. Add `my %REVOKED_FAMILIES;` alongside their existing
`%REFRESH`, and make the same two changes, reading `$b->{family_id}` /
`$REFRESH{$h}{b}{family_id}` per each file's own convention.

- [ ] **Step 4: Make the engine honour a refused create**

In `lib/.../Server.pm`, `_issue_token_pair`, the `create_refresh_token` call
becomes checked:

```perl
    my $created = $self->store->create_refresh_token(
        $self->_hash_token($refresh),
        {
            client_id => $binding->{client_id},
            subject   => $binding->{subject},
            scope     => $binding->{scope},
            resource  => $binding->{resource},
            family_id => $binding->{family_id},
        },
        $self->_now + $self->refresh_ttl,
    );
    # The family was revoked while this rotation was in flight: a concurrent
    # replay was detected. Same generic error as any other dead token.
    $self->_grant_error('unknown or revoked refresh token') unless $created;
```

The access token minted just above is discarded and never reaches the client.

- [ ] **Step 5: Run the test and the suite**

Run: `prove -l t/server-refresh-family.t && prove -lr t`
Expected: both PASS.

- [ ] **Step 6: Update the role POD**

Replace the `create_refresh_token` retention/contract wording so it states the
refusal, and rewrite the concurrency note, which currently tells implementers
to do something they cannot:

```pod
=head2 create_refresh_token( $token_hash, \%binding, $expires_at )

Persist a refresh token by its hash (never the raw token). C<\%binding> carries
C<client_id>, C<subject>, C<scope>, C<resource> and C<family_id>. Returns true
when the token was persisted.

B<Returns false, persisting nothing, if C<family_id> names a revoked family.>
A rotation already in flight when C<revoke_family> runs would otherwise create
its successor afterwards, leaving a live token in a family the server believes
it killed, and an attacker who races two refreshes with a stolen token can
force exactly that. The check and the insert MUST be atomic: they are one
method call so a single statement can do both, e.g. an C<INSERT ... WHERE NOT
EXISTS> against the revoked-families record.

C<family_id> is an opaque string identifying the rotation chain this token
belongs to: it is minted when an authorization code is exchanged and inherited
by every token rotated from it. The Store MUST persist it and MUST be able to
find rows by it (see C<revoke_family>).
```

and for `revoke_family`, state that it marks the family:

```pod
Revoke every refresh token sharing C<$family_id>, live or already tombstoned,
B<and record the family itself as revoked> so that a rotation in flight cannot
create a successor into it afterwards (see C<create_refresh_token>). Return the
number newly revoked. Idempotent: revoking an already-revoked family returns 0
and is not an error. An implementation may use a single flag for both the
rotation tombstone and revocation, in which case an already-tombstoned token
counts as already revoked and is not counted again.
```

Delete the old "Wrap both operations in a transaction if the backend supports
it" advice from `rotate_refresh_token`'s note: it is not achievable across two
engine-called methods and it implied a safety that did not exist. Say instead
that each Store method must be individually atomic, and that the
create-refuses-revoked-family rule is what makes the pair safe.

- [ ] **Step 7: Correct the LIMITATIONS claim**

`lib/.../AuthorizationServer.pm` currently says a concurrent double-refresh
"will revoke the family". That is now true, but only because of this task; it
was false before. Check the paragraph still reads correctly and states that the
in-flight rotation fails rather than surviving.

- [ ] **Step 8: Verify**

```bash
prove -lr t
PERL_CRITIC_TEST=1 prove -l t/perl_critic.t
grep -rnP '[^\x00-\x7F]' --include='*.pm' --include='*.t' --include='*.md' .
```

- [ ] **Step 9: Ask before committing, then commit**

Proposed message:

```text
Stop a raced replay leaving a live token in a dead family

revoke_family swept the rows that existed when it ran, so a rotation already in
flight created its successor afterwards and that successor was born live into
the revoked family. It then rotated indefinitely. An attacker fires two
refreshes with a stolen token and retries until the loser's revoke lands in the
winner's gap: the legitimate client is locked out, the attacker keeps the only
live token, and the logs say the family was revoked. Strictly worse than having
no reuse detection.

Revocation is now a property of the family rather than of its rows, and
create_refresh_token refuses to birth a successor into a revoked one. Both are
single Store calls, so an implementer can make them atomic; the old advice to
wrap rotate and create in a transaction was not achievable across two methods
the engine calls separately, and is gone.
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| AMENDMENT: family marker, create refuses revoked family | 5 |
| AMENDMENT: role POD concurrency note rewritten | 5 |

| Spec section | Task |
| --- | --- |
| `rotate_refresh_token` three outcomes | 1 |
| Tombstone retention until `expires_at` | 1 (code + role POD) |
| `create_refresh_token` gains `family_id` | 2 |
| `revoke_family` new required verb | 3 |
| Family birth at code exchange / inherit on refresh | 2 |
| `_issue_token_pair` croaks without `family_id` | 2 |
| Reuse path revokes then errors | 3 |
| Generic `invalid_grant`, no oracle | 3 (test + code) |
| `revoke_family` failure surfaces as 500 | 3 (comment; no test, see below) |
| `jti` in fixed payload | 4 |
| LIMITATIONS rewrite | 3 |
| Concurrent-refresh false positive documented | 3 (LIMITATIONS) |
| Replay kills live token | 3 |
| Cross-family isolation | 3 |
| `family_id` survives chain | 2 |
| Deep replay | 3 |
| Unknown revokes nothing | 3 |
| `jti` unique | 4 |
| `revoke_family` idempotent | 3 |
| Mutation-check the headline test | 3, step 8 |

**Known gaps, called out rather than hidden:**

- **The "revoke_family failure is a 500" decision has no test.** Provoking it
  needs a Store that throws, and the engine simply does not catch, so the test
  would assert that Perl propagates an exception. Low value. The behaviour is
  a consequence of not writing a `try`, and the comment records why.
- **The tombstone-present-before-expiry characterisation test** from the spec
  is covered implicitly by the reuse tests (a replay only reports `reused` if
  the tombstone survived). A dedicated test would assert Store internals. Skip.

**Type consistency:** `rotate_refresh_token` returns
`{ binding => ..., reused => ... }` in Task 1's role POD, Task 1's three Store
implementations, and Task 3's engine consumption. `revoke_family($family_id)`
returns a count in the role POD, all three Stores, and the idempotency test.
`family_id` is the key name in Task 2's engine, Task 2's role POD and Task 3's
Store lookups. Note the Store implementations disagree on the binding key by
pre-existing convention: `StubStore` uses `binding`, the other two use `b`.
The plan's code respects each file's own convention.

**Placeholder scan:** none. Every code step carries the code.

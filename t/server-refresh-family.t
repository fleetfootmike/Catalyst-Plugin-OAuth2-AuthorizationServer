use v5.36;
use Test::More;
use Test::Fatal;
use Digest::SHA qw/sha256/;
use MIME::Base64 qw/encode_base64url/;
use lib 't/lib';
use StubStore;
use TestApp::Model::OAuthStore;

my $class = 'Catalyst::Plugin::OAuth2::AuthorizationServer::Server';
require_ok($class);

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

# every stored binding, in no particular order, for assertions about
# family identity
sub bindings ( $eng ) {
    my $r = $eng->store->refresh;
    return [ map { $r->{$_}{binding} } keys %$r ];
}

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

# A tombstone (rotated once, so revoked) that later expires must report
# undef, not reused: the expiry check has to run before the revoked check,
# or the reuse-detection window becomes unbounded instead of == refresh_ttl.
{
    my $store = StubStore->new;
    $store->create_refresh_token( 'h2',
        { client_id => 'c1', subject => 'user-9' }, time + 3600 );

    my $first = $store->rotate_refresh_token('h2');
    ok( $first, 'first rotation of h2 succeeds' );
    ok( !$first->{reused}, 'first rotation is not a replay' );

    # Backdate the now-revoked tombstone's exp into the past.
    $store->refresh->{h2}{exp} = time - 1;

    is( $store->rotate_refresh_token('h2'), undef,
        'a rotated-then-expired tombstone reports undef, not reused' );
}

# TestApp::Model::OAuthStore is a second Store implementation, backed by a
# process-wide %REFRESH hash (not per-instance like StubStore's). It names
# its binding key "b" internally but must still wrap it as "binding" on the
# way out. Use distinctive hashes so this cannot collide with rows any other
# test in this process happens to leave behind.
{
    my $store = TestApp::Model::OAuthStore->new;
    $store->create_refresh_token( 'oauthstore-h1-9f3a2e',
        { client_id => 'c1', subject => 'user-oauthstore-9' }, time + 3600 );

    my $first = $store->rotate_refresh_token('oauthstore-h1-9f3a2e');
    is( ref $first, 'HASH', 'rotate returns a hashref' );
    is( $first->{binding}{subject}, 'user-oauthstore-9',
        'binding comes back wrapped' );
    ok( !$first->{reused}, 'a live token is not flagged as reused' );

    my $replay = $store->rotate_refresh_token('oauthstore-h1-9f3a2e');
    ok( $replay,           'a replayed token is not undef' );
    ok( $replay->{reused}, 'a replayed token is flagged reused' );
    is( $replay->{binding}{subject}, 'user-oauthstore-9',
        'the replay carries the binding so the family can be found' );
}

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

    my @all_bindings = @{ bindings($eng) };
    ok( ( scalar( grep { defined $_->{family_id} } @all_bindings )
            == scalar @all_bindings ),
        'every binding in the chain has a defined family_id' );

    my %families = map { ( $_->{family_id} // 'MISSING' ) => 1 } @all_bindings;
    is( scalar keys %families, 1,
        'one family_id across the whole rotation chain' );
    is( ( keys %families )[0], $born, 'and it is the family born at exchange' );
}

# two independent code exchanges must not share a family_id: a non-distinct
# family_id would mean, once revoke_family is wired up, that a replay by any
# attacker revokes every refresh token for every user.
{
    my $eng1 = fresh_engine();
    my $eng2 = fresh_engine();

    first_pair( $eng1, $VERIFIER, 'user-a' );
    first_pair( $eng2, $VERIFIER, 'user-b' );

    my ($family1) = map { $_->{family_id} } @{ bindings($eng1) };
    my ($family2) = map { $_->{family_id} } @{ bindings($eng2) };

    ok( defined $family1 && length $family1,
        'first exchange births a family_id' );
    ok( defined $family2 && length $family2,
        'second exchange births a family_id' );
    isnt( $family1, $family2,
        'two independent code exchanges get different family_ids' );
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

done_testing;

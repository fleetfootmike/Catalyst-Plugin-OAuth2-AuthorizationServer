use v5.36;
use Test::More;
use Test::Fatal;
use lib 't/lib';
use StubStore;
use TestApp::Model::OAuthStore;

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

done_testing;

use v5.36;
use Test::More;
use Test::Fatal;
use Crypt::JWT qw/decode_jwt/;

my $class = 'Catalyst::Plugin::OAuth2::AuthorizationServer::Server';
require_ok($class);

# a trivial stub store object (no methods exercised here)
package T::Store { use Moo;
    with 'Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store';
    sub create_client {} sub find_client {}
    sub save_authorization_request {} sub take_authorization_request {}
    sub create_auth_code {} sub consume_auth_code {}
    sub create_refresh_token {} sub rotate_refresh_token {}
    sub revoke_refresh_tokens_for_subject {}
}
package main;

my $key = 'test-signing-key-0123456789';
my $eng = $class->new(
    store       => T::Store->new,
    signing_key => $key,
    issuer      => 'https://as.example',
    resource    => 'https://rs.example/mcp',
);

# BUILD validation
like(
    exception {
        $class->new( store => T::Store->new, signing_key => $key,
            issuer => 'i', resource => [] );
    },
    qr/resource/,
    'empty resource arrayref rejected'
);

# mint a token and verify the claims round-trip with the same key
my $before = time;
my $jwt = $eng->mint_access_token({
    sub   => 'user-42',
    scope => 'gobby:read',
});
ok( length $jwt, 'mint returns a token string' );

my $claims = decode_jwt( token => $jwt, key => $key );
is( $claims->{sub},   'user-42',                  'sub claim' );
is( $claims->{scope}, 'gobby:read',               'scope claim' );
is( $claims->{iss},   'https://as.example',       'iss from issuer' );
is( $claims->{aud},   'https://rs.example/mcp',   'aud from resource' );
ok( $claims->{exp} >= $before + 900 && $claims->{exp} <= time + 900 + 2,
    'exp ~ now + access_ttl' );

# an explicit aud overrides the configured-resource default
my $claims_aud = decode_jwt(
    token => $eng->mint_access_token( { sub => 'u' }, 'https://other/api' ),
    key   => $key );
is( $claims_aud->{aud}, 'https://other/api', 'explicit aud honoured' );

# random tokens are URL-safe and unique
my %seen;
for ( 1 .. 100 ) {
    my $t = $eng->_random_token(32);
    like( $t, qr/\A[A-Za-z0-9_-]+\z/, 'token is base64url' );
    ok( !$seen{$t}++, 'token unique' );
}

done_testing;

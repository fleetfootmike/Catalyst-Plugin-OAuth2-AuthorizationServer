use v5.36;
use Test::More;
use Test::Fatal;
use lib 't/lib';
use StubStore;

my $class = 'Catalyst::Plugin::OAuth2::AuthorizationServer::Server';
require_ok($class);

sub engine (%over) {
    return $class->new(
        store       => StubStore->new,
        signing_key => 'k' x 32,
        issuer      => 'https://as.example',
        resource    => 'https://rs.example/mcp',
        %over,
    );
}

# happy path: generates a client_id, echoes metadata, persists via the store
{
    my $eng = engine();
    my $client = $eng->register_client({
        redirect_uris => ['https://app.example/cb'],
        client_name   => 'Test',
    });
    like( $client->{client_id}, qr/\A[A-Za-z0-9_-]+\z/, 'generated client_id' );
    is_deeply( $client->{redirect_uris}, ['https://app.example/cb'], 'redirect kept' );
    is( $eng->store->find_client( $client->{client_id} )->{client_name},
        'Test', 'persisted via store' );
}

# missing redirect_uris -> invalid_client_metadata
{
    my $e = exception { engine()->register_client({ client_name => 'x' }) };
    isa_ok( $e, 'Catalyst::Plugin::OAuth2::AuthorizationServer::Error' );
    is( $e->error, 'invalid_client_metadata', 'no redirect_uris rejected' );
}

# too many redirect_uris
{
    my $e = exception {
        engine( redirect_uris_max => 2 )->register_client({
            redirect_uris => [ map { "https://a/$_" } 1 .. 3 ],
        });
    };
    is( $e->error, 'invalid_client_metadata', 'over redirect_uris_max rejected' );
}

# over-long redirect_uri
{
    my $long = 'https://a/' . ( 'x' x 3000 );
    my $e = exception {
        engine->register_client({ redirect_uris => [$long] });
    };
    is( $e->error, 'invalid_client_metadata', 'over-long redirect_uri rejected' );
}

# oversize metadata document
{
    my $e = exception {
        engine( metadata_max_bytes => 64 )->register_client({
            redirect_uris => ['https://app.example/cb'],
            blob          => 'y' x 200,
        });
    };
    is( $e->error, 'invalid_client_metadata', 'oversize metadata rejected' );
}

done_testing;

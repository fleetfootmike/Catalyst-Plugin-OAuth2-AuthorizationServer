package Catalyst::Plugin::OAuth2::AuthorizationServer::Server;
use v5.36;
use Moo;
use Carp ();
use Crypt::JWT qw/encode_jwt/;
use Bytes::Random::Secure qw/random_bytes/;
use MIME::Base64 qw/encode_base64url/;
use JSON::MaybeXS ();
use Catalyst::Plugin::OAuth2::AuthorizationServer::Error;
use namespace::clean;

our $VERSION = '0.001';

has store       => ( is => 'ro', required => 1 );
has signing_key => ( is => 'ro', required => 1 );
has issuer      => ( is => 'ro', required => 1 );
has resource    => ( is => 'ro', required => 1 );

has jwt_alg     => ( is => 'ro', default => 'HS256' );
has access_ttl  => ( is => 'ro', default => 900 );
has refresh_ttl => ( is => 'ro', default => 2592000 );
has code_ttl    => ( is => 'ro', default => 60 );

has scopes_supported        => ( is => 'ro' );          # arrayref or undef
has metadata_max_bytes      => ( is => 'ro', default => 8192 );
has redirect_uris_max       => ( is => 'ro', default => 5 );
has redirect_uri_max_length => ( is => 'ro', default => 2048 );

has authorize_endpoint    => ( is => 'lazy' );
has token_endpoint        => ( is => 'lazy' );
has registration_endpoint => ( is => 'lazy' );

sub _build_authorize_endpoint    ( $self ) { $self->issuer . '/authorize' }
sub _build_token_endpoint        ( $self ) { $self->issuer . '/token' }
sub _build_registration_endpoint ( $self ) { $self->issuer . '/register' }

sub BUILD ( $self, $args ) {
    Carp::croak 'resource must be a non-empty scalar or arrayref'
        unless @{ $self->_resource_list };
    for my $ttl (qw/access_ttl refresh_ttl code_ttl/) {
        Carp::croak "$ttl must be a positive integer"
            unless $self->$ttl && $self->$ttl > 0;
    }
}

# resource may be a scalar or arrayref; normalise to a list.
sub _resource_list ( $self ) {
    my $r = $self->resource;
    return ref $r eq 'ARRAY' ? $r : defined $r && length $r ? [$r] : [];
}

sub _now ( $self ) { return time }

# A URL-safe random token of $bytes entropy, base64url with no padding.
sub _random_token ( $self, $bytes = 32 ) {
    my $b64 = encode_base64url( random_bytes($bytes) );
    $b64 =~ s/=+\z//;       # encode_base64url already drops padding; belt + braces
    return $b64;
}

# Mint a signed access-token JWT. Caller supplies sub + scope (+ any extras);
# the engine stamps iss, aud, iat, exp.
sub mint_access_token ( $self, $claims, $aud = undef ) {
    my $now = $self->_now;
    # aud is the AUTHORIZED resource (from the code/refresh binding); fall back
    # to the configured resource list only when the caller passes none.
    my @aud =
          !defined $aud       ? @{ $self->_resource_list }
        : ref $aud eq 'ARRAY' ? @$aud
        :                       ($aud);
    my %payload = (
        %$claims,
        iss => $self->issuer,
        aud => ( @aud == 1 ? $aud[0] : \@aud ),
        iat => $now,
        exp => $now + $self->access_ttl,
    );
    return encode_jwt(
        payload => \%payload,
        alg     => $self->jwt_alg,
        key     => $self->signing_key,
    );
}

sub _invalid_metadata ( $self, $desc ) {
    Catalyst::Plugin::OAuth2::AuthorizationServer::Error->throw(
        error             => 'invalid_client_metadata',
        error_description => $desc,
        http_status       => 400,
    );
}

sub register_client ( $self, $metadata ) {
    my $uris = $metadata->{redirect_uris};
    $self->_invalid_metadata('redirect_uris is required')
        unless ref $uris eq 'ARRAY' && @$uris;
    $self->_invalid_metadata('too many redirect_uris')
        if @$uris > $self->redirect_uris_max;
    for my $u (@$uris) {
        $self->_invalid_metadata('redirect_uri not a string')
            if ref $u || !defined $u || !length $u;
        $self->_invalid_metadata('redirect_uri too long')
            if length $u > $self->redirect_uri_max_length;
    }

    my $json = JSON::MaybeXS->new( utf8 => 1, canonical => 1 );
    $self->_invalid_metadata('client metadata too large')
        if length( $json->encode($metadata) ) > $self->metadata_max_bytes;

    my $client = { %$metadata, client_id => $self->_random_token(16) };
    return $self->store->create_client($client);
}

1;

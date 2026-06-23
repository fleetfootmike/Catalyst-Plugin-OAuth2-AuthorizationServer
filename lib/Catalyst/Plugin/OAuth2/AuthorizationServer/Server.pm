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

# Authorize errors are redirect-safe only AFTER the client and redirect_uri
# have been validated (RFC 6749 §4.1.2.1). Pass redirect_uri (+ state) for
# those so the seam can 302 the error back to the client; omit it for
# unknown-client / bad-redirect errors so the seam renders them directly and
# never redirects to an untrusted URI.
sub _authz_error ( $self, $error, $desc, %opt ) {
    Catalyst::Plugin::OAuth2::AuthorizationServer::Error->throw(
        error             => $error,
        error_description => $desc,
        ( exists $opt{redirect_uri} ? ( redirect_uri => $opt{redirect_uri} ) : () ),
        ( exists $opt{state}        ? ( state        => $opt{state} )        : () ),
        http_status       => 400,
    );
}

sub validate_authorize ( $self, $params ) {
    my $state = $params->{state};

    # Client + redirect_uri first; their failures are NOT redirect-safe.
    my $client = $self->store->find_client( $params->{client_id} // '' );
    $self->_authz_error( 'invalid_client', 'unknown client' ) unless $client;

    my $redirect = $params->{redirect_uri} // '';
    my $known = $client->{redirect_uris} || [];
    $self->_authz_error( 'invalid_client', 'redirect_uri mismatch' )
        unless grep { $_ eq $redirect } @$known;

    # From here the redirect_uri is trusted, so further errors are redirect-safe.
    my %rd = ( redirect_uri => $redirect, state => $state );

    $self->_authz_error( 'invalid_request', 'response_type must be code', %rd )
        unless ( $params->{response_type} // '' ) eq 'code';

    my $challenge = $params->{code_challenge};
    $self->_authz_error( 'invalid_request', 'code_challenge required', %rd )
        unless defined $challenge && length $challenge;
    $self->_authz_error( 'invalid_request', 'code_challenge_method must be S256', %rd )
        unless ( $params->{code_challenge_method} // '' ) eq 'S256';

    my $scope = $params->{scope};
    if ( defined $scope && length $scope && $self->scopes_supported ) {
        my %ok = map { $_ => 1 } @{ $self->scopes_supported };
        for my $s ( split /\s+/, $scope ) {
            $self->_authz_error( 'invalid_scope', "unsupported scope: $s", %rd )
                unless $ok{$s};
        }
    }

    my $resource = $params->{resource} // '';
    my %valid_res = map { $_ => 1 } @{ $self->_resource_list };
    $self->_authz_error( 'invalid_target', 'unknown resource', %rd )
        unless $valid_res{$resource};

    my $rid  = $self->_random_token(24);
    my $data = {
        client_id             => $params->{client_id},
        redirect_uri          => $redirect,
        response_type         => 'code',
        code_challenge        => $challenge,
        code_challenge_method => 'S256',
        scope                 => $scope,
        resource              => $resource,
        state                 => $state,
    };
    $self->store->save_authorization_request(
        $rid, $data, $self->_now + 600 );
    return { request_id => $rid };
}

sub issue_code ( $self, $subject, $request_id ) {
    my $req = $self->store->take_authorization_request( $request_id );
    Catalyst::Plugin::OAuth2::AuthorizationServer::Error->throw(
        error             => 'invalid_request',
        error_description => 'unknown or expired authorization request',
        http_status       => 400,
    ) unless $req;

    my $code    = $self->_random_token(32);
    my $binding = {
        client_id      => $req->{client_id},
        subject        => $subject,
        redirect_uri   => $req->{redirect_uri},
        code_challenge => $req->{code_challenge},
        scope          => $req->{scope},
        resource       => $req->{resource},
    };
    $self->store->create_auth_code(
        $code, $binding, $self->_now + $self->code_ttl );

    return {
        code         => $code,
        redirect_uri => $req->{redirect_uri},
        state        => $req->{state},
    };
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

package Catalyst::Plugin::OAuth2::AuthorizationServer;
use v5.36;
use Scalar::Util qw/blessed/;
use JSON::MaybeXS ();
use Try::Tiny;
use URI;
use Catalyst::Plugin::OAuth2::AuthorizationServer::Server;
use Catalyst::Plugin::OAuth2::AuthorizationServer::Error;

our $VERSION = '0.001';

my $CONFIG_KEY = 'Catalyst::Plugin::OAuth2::AuthorizationServer';
my $JSON = JSON::MaybeXS->new( utf8 => 1, canonical => 1 );

# Build a per-request engine from app config. Stateless: the only stateful
# collaborator is the app-provided Store, resolved fresh each call.
sub _oauth_engine ( $c ) {
    my %cfg = %{ $c->config->{$CONFIG_KEY} // {} };

    my $store = delete $cfg{store};
    $store = $c->model($store) if defined $store && !blessed $store;
    Catalyst::Exception->throw("OAuth2 AS: no Store configured")
        unless blessed $store;

    return Catalyst::Plugin::OAuth2::AuthorizationServer::Server->new(
        store => $store, %cfg );
}

# Slurp + decode a JSON request body (DCR). Returns a hashref or throws a
# 400 invalid_request.
sub _oauth_json_body ( $c ) {
    my $body = $c->request->body;
    my $raw  = q{};
    if ( defined $body && ref $body ) {
        binmode $body; seek $body, 0, 0; local $/ = undef; $raw = <$body> // q{};
    }
    elsif ( defined $body ) { $raw = $body }
    my $data = try { $JSON->decode($raw) }
        catch { undef };
    Catalyst::Plugin::OAuth2::AuthorizationServer::Error->throw(
        error => 'invalid_request', error_description => 'invalid JSON body',
        http_status => 400 )
        unless ref $data eq 'HASH';
    return $data;
}

sub oauth_error ( $c, $error, $status = 400, $desc = undef ) {
    my %body = ( error => $error );
    $body{error_description} = $desc if defined $desc;
    my $res = $c->response;
    $res->status($status);
    $res->content_type('application/json');
    $res->header( 'Cache-Control' => 'no-store' );
    $res->body( $JSON->encode( \%body ) );
    return;
}

# Render any caught error: our structured Error -> its envelope; anything else
# -> a generic 500 server_error (text never leaked).
sub _oauth_render_error ( $c, $err ) {
    if ( blessed $err
        && $err->isa('Catalyst::Plugin::OAuth2::AuthorizationServer::Error') )
    {
        my ( $body, $status ) = $err->to_response;
        my $res = $c->response;
        $res->status($status);
        $res->content_type('application/json');
        $res->header( 'Cache-Control' => 'no-store' );
        $res->body( $JSON->encode($body) );
        return;
    }
    return $c->oauth_error( 'server_error', 500 );
}

sub oauth_metadata ( $c ) {
    my $doc = $c->_oauth_engine->metadata_document;
    my $res = $c->response;
    $res->status(200);
    $res->content_type('application/json');
    $res->body( $JSON->encode($doc) );
    return;
}

sub oauth_register ( $c ) {
    return try {
        if ( $c->can('oauth_dcr_allow_registration')
            && !$c->oauth_dcr_allow_registration )
        {
            return $c->oauth_error( 'too_many_requests', 429,
                'registration rate limit exceeded' );
        }
        my $metadata = $c->_oauth_json_body;
        my $client   = $c->_oauth_engine->register_client($metadata);
        my $res = $c->response;
        $res->status(201);
        $res->content_type('application/json');
        $res->header( 'Cache-Control' => 'no-store' );
        $res->body( $JSON->encode($client) );
        return;
    }
    catch { $c->_oauth_render_error($_) };
}

sub oauth_authorize ( $c ) {
    return try {
        my %params = %{ $c->request->query_parameters };
        my $out    = $c->_oauth_engine->validate_authorize( \%params );
        # Hand off to the app's authn/consent hook with the opaque request_id.
        return $c->oauth_authenticate( $out->{request_id} );
    }
    catch {
        my $err = $_;
        # Redirect-safe authorize errors (client + redirect_uri already valid)
        # go back to the client per RFC 6749 §4.1.2.1; the rest render directly.
        if ( blessed $err
            && $err->isa('Catalyst::Plugin::OAuth2::AuthorizationServer::Error')
            && defined $err->redirect_uri )
        {
            my $uri = URI->new( $err->redirect_uri );
            $uri->query_form(
                error => $err->error,
                ( defined $err->error_description
                    ? ( error_description => $err->error_description ) : () ),
                ( defined $err->state ? ( state => $err->state ) : () ),
            );
            $c->response->redirect( $uri, 302 );
            return;
        }
        return $c->_oauth_render_error($err);
    };
}

# Called BY the app once the user has consented.
sub oauth_issue_code ( $c, $subject, $request_id ) {
    return $c->_oauth_engine->issue_code( $subject, $request_id );
}

sub oauth_token ( $c ) {
    return try {
        my %p   = %{ $c->request->body_parameters };
        my $gt  = $p{grant_type} // '';
        my $eng = $c->_oauth_engine;
        my $tok =
              $gt eq 'authorization_code' ? $eng->exchange_authorization_code( \%p )
            : $gt eq 'refresh_token'      ? $eng->refresh( \%p )
            : Catalyst::Plugin::OAuth2::AuthorizationServer::Error->throw(
                error => 'unsupported_grant_type',
                error_description => "unsupported grant_type: $gt",
                http_status => 400 );
        my $res = $c->response;
        $res->status(200);
        $res->content_type('application/json');
        $res->header( 'Cache-Control' => 'no-store' );
        $res->body( $JSON->encode($tok) );
        return;
    }
    catch { $c->_oauth_render_error($_) };
}

=head1 NAME

Catalyst::Plugin::OAuth2::AuthorizationServer - MCP-profile OAuth 2.1
Authorization Server plugin for Catalyst

=head1 DESCRIPTION

Adds an OAuth 2.1 Authorization Server (the MCP profile: public PKCE-S256
client, C<authorization_code> + C<refresh_token> grants, Dynamic Client
Registration, and AS metadata) to a Catalyst application. The protocol engine
lives in L<Catalyst::Plugin::OAuth2::AuthorizationServer::Server>; this module
is the thin Catalyst seam.

=head1 METHODS

=head2 oauth_metadata

Render the RFC 8414 Authorization Server Metadata document as C<200 application/json>.

=head2 oauth_register

Dynamic Client Registration endpoint (RFC 7591). Calls the optional app hook
C<oauth_dcr_allow_registration($c)> first — if it returns false, responds 429.
Reads a JSON body, calls the engine's C<register_client>, and writes C<201>
JSON with C<Cache-Control: no-store>.

=head2 oauth_authorize

Validates the authorize query parameters via the engine. On success, calls the
app hook C<oauth_authenticate($c, $request_id)> (see below). On a redirect-safe
error (valid client + redirect_uri already confirmed), redirects to the
C<redirect_uri> with C<error=> and C<state=> params (RFC 6749 §4.1.2.1).
Otherwise renders a JSON error envelope directly.

=head2 oauth_issue_code( $subject, $request_id )

Called BY the app (typically inside C<oauth_authenticate>) once the user has
consented. Returns C<{ code, redirect_uri, state }>.

=head2 oauth_token

Reads form parameters, dispatches C<authorization_code> or C<refresh_token>
grants via the engine, writes C<200> JSON with C<Cache-Control: no-store>.

=head2 oauth_error( $error, $status, $desc )

Render a bare OAuth error envelope. C<$status> defaults to 400; C<$desc> is
optional.

=head1 APP HOOKS

The consuming Catalyst application must provide:

=head2 oauth_authenticate( $c, $request_id )

Called by C<oauth_authorize> after the request is validated. A real app would
redirect to a login/consent page. In that page handler, call
C<< $c->oauth_issue_code($subject, $request_id) >> and redirect to the
returned C<redirect_uri> carrying the C<code> (and C<state>).

=head2 oauth_dcr_allow_registration( $c )   (optional)

If present and returns false, C<oauth_register> responds 429
C<too_many_requests>. Use for rate-limiting DCR.

=cut

1;

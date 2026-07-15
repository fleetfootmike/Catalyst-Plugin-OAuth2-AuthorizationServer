package Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store;
use v5.36;
use Moo::Role;

our $VERSION = '0.002';

requires qw/
    create_client
    find_client
    save_authorization_request
    take_authorization_request
    create_auth_code
    consume_auth_code
    create_refresh_token
    rotate_refresh_token
    revoke_refresh_tokens_for_subject
/;

=head1 NAME

Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store - storage contract

=head1 DESCRIPTION

Storage-agnostic persistence contract for the Authorization Server. The host
app provides an object consuming this Role. All times are epoch seconds.

=head1 REQUIRED METHODS

=head2 create_client( \%metadata )

Persist a new client (the engine has already generated and inserted
C<client_id> into the metadata). Return the stored client hashref (must
contain C<client_id> and C<redirect_uris>).

=head2 find_client( $client_id )

Return the stored client hashref for C<$client_id>, or undef if unknown.

=head2 save_authorization_request( $request_id, \%data, $expires_at )

Persist the validated authorize request under the opaque C<$request_id> with
an absolute C<$expires_at>. Return true.

=head2 take_authorization_request( $request_id )

Atomically fetch-and-delete (single-use) the saved request. Return the
C<\%data> hashref, or undef if missing or expired. The atomic fetch-and-delete
requirement prevents authorization-request replay.

=head2 create_auth_code( $code, \%binding, $expires_at )

Persist a single-use authorization code. C<\%binding> carries C<client_id>,
C<subject>, C<redirect_uri>, C<code_challenge>, C<scope>, C<resource>. Return
true.

=head2 consume_auth_code( $code )

Atomically fetch-and-delete the code's binding (single-use). Return the
C<\%binding>, or undef if unknown/expired/already used. The same atomic
fetch-and-delete requirement prevents authorization-code replay.

=head2 create_refresh_token( $token_hash, \%binding, $expires_at )

Persist a refresh token by its hash (never the raw token). C<\%binding> carries
C<client_id>, C<subject>, C<scope>, C<resource>. Return true.

=head2 rotate_refresh_token( $token_hash )

Atomically validate-and-revoke the refresh token identified by C<$token_hash>,
returning its C<\%binding> (so the engine can mint a fresh pair), or undef if
unknown/expired/already revoked.

B<Concurrency note:> a non-atomic implementation enables refresh-token replay
under concurrent requests. The engine calls C<create_refresh_token> immediately
after C<rotate_refresh_token> with no transactional envelope: a crash between
the two calls will invalidate the session. Wrap both operations in a
transaction if the backend supports it.

=head2 revoke_refresh_tokens_for_subject( $subject )

Revoke all refresh tokens for C<$subject> (e.g. on deactivation or password
change). Return the number revoked.

=cut

1;

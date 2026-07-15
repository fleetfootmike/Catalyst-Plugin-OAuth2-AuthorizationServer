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
    revoke_family
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
C<client_id>, C<subject>, C<scope>, C<resource> and C<family_id>. Return true.

C<family_id> is an opaque string identifying the rotation chain this token
belongs to: it is minted when an authorization code is exchanged and inherited
by every token rotated from it. The Store MUST persist it and MUST be able to
find rows by it (see C<revoke_family>).

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

=head2 revoke_family( $family_id )

Revoke every refresh token sharing C<$family_id>, live or already tombstoned.
Return the number newly revoked. Idempotent: revoking an already-revoked
family returns 0 and is not an error.

An implementation may use a single flag for both "tombstoned by rotation" and
"revoked by family": in that case an already-tombstoned token counts as
already revoked, and is not counted again.

Called when C<rotate_refresh_token> reports a replay. Revoking the family is
the only defence the server has against a stolen refresh token, because it
cannot tell the legitimate client from the attacker.

=head2 revoke_refresh_tokens_for_subject( $subject )

Revoke all refresh tokens for C<$subject> (e.g. on deactivation or password
change). Return the number revoked.

=cut

1;

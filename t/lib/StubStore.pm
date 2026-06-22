package StubStore;
use v5.36;
use Moo;
with 'Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store';

has clients  => ( is => 'ro', default => sub { {} } );
has requests => ( is => 'ro', default => sub { {} } );
has codes    => ( is => 'ro', default => sub { {} } );
has refresh  => ( is => 'ro', default => sub { {} } );

sub create_client ( $self, $client ) {
    $self->clients->{ $client->{client_id} } = $client;
    return $client;
}
sub find_client ( $self, $id ) { return $self->clients->{$id} }

sub save_authorization_request ( $self, $rid, $data, $exp ) {
    $self->requests->{$rid} = { data => $data, exp => $exp };
    return 1;
}
sub take_authorization_request ( $self, $rid ) {
    my $row = delete $self->requests->{$rid} or return undef;
    return undef if $row->{exp} < time;
    return $row->{data};
}

sub create_auth_code ( $self, $code, $binding, $exp ) {
    $self->codes->{$code} = { binding => $binding, exp => $exp };
    return 1;
}
sub consume_auth_code ( $self, $code ) {
    my $row = delete $self->codes->{$code} or return undef;
    return undef if $row->{exp} < time;
    return $row->{binding};
}

sub create_refresh_token ( $self, $hash, $binding, $exp ) {
    $self->refresh->{$hash} = { binding => $binding, exp => $exp };
    return 1;
}
sub rotate_refresh_token ( $self, $hash ) {
    my $row = delete $self->refresh->{$hash} or return undef;
    return undef if $row->{exp} < time;
    return $row->{binding};
}
sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %{ $self->refresh } ) {
        if ( ( $self->refresh->{$h}{binding}{subject} // '' ) eq $subject ) {
            delete $self->refresh->{$h};
            $n++;
        }
    }
    return $n;
}

1;

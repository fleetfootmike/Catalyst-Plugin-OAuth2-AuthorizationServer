package Example::OAuthAS::Model::Store;
use v5.36;
use Moo;
extends 'Catalyst::Model';
with 'Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store';

# Process-wide in-memory storage: fine for a single-process example, NOT for
# production (use a real datastore there).
my ( %CLIENTS, %REQUESTS, %CODES, %REFRESH );

sub create_client ( $self, $client ) {
    $CLIENTS{ $client->{client_id} } = $client;
    return $client;
}

sub find_client ( $self, $id ) { return $CLIENTS{ $id // '' } }

sub save_authorization_request ( $self, $rid, $data, $exp ) {
    $REQUESTS{$rid} = { data => $data, exp => $exp };
    return 1;
}

sub take_authorization_request ( $self, $rid ) {
    my $row = delete $REQUESTS{$rid} or return undef;
    return $row->{exp} < time ? undef : $row->{data};
}

sub create_auth_code ( $self, $code, $binding, $exp ) {
    $CODES{$code} = { b => $binding, exp => $exp };
    return 1;
}

sub consume_auth_code ( $self, $code ) {
    my $row = delete $CODES{$code} or return undef;
    return $row->{exp} < time ? undef : $row->{b};
}

sub create_refresh_token ( $self, $hash, $binding, $exp ) {
    $REFRESH{$hash} = { b => $binding, exp => $exp };
    return 1;
}

sub rotate_refresh_token ( $self, $hash ) {
    my $row = delete $REFRESH{$hash} or return undef;
    return $row->{exp} < time ? undef : $row->{b};
}

sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        ( $REFRESH{$h}{b}{subject} // '' ) eq $subject
            and delete $REFRESH{$h}
            and $n++;
    }
    return $n;
}

1;

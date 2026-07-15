package TestApp::Model::OAuthStore;
use v5.36;
use Moo;
extends 'Catalyst::Model';
with 'Catalyst::Plugin::OAuth2::AuthorizationServer::Role::Store';

# Process-wide in-memory storage (one app instance per test process).
my %CLIENTS; my %REQUESTS; my %CODES; my %REFRESH;

sub create_client ( $self, $client ) {
    $CLIENTS{ $client->{client_id} } = $client; return $client;
}
sub find_client ( $self, $id ) { return $CLIENTS{ $id // '' } }

sub save_authorization_request ( $self, $rid, $data, $exp ) {
    $REQUESTS{$rid} = { data => $data, exp => $exp }; return 1;
}
sub take_authorization_request ( $self, $rid ) {
    my $row = delete $REQUESTS{$rid} or return undef;
    return $row->{exp} < time ? undef : $row->{data};
}
sub create_auth_code ( $self, $code, $b, $exp ) {
    $CODES{$code} = { b => $b, exp => $exp }; return 1;
}
sub consume_auth_code ( $self, $code ) {
    my $row = delete $CODES{$code} or return undef;
    return $row->{exp} < time ? undef : $row->{b};
}
sub create_refresh_token ( $self, $hash, $b, $exp ) {
    $REFRESH{$hash} = { b => $b, exp => $exp, revoked => 0 }; return 1;
}
sub rotate_refresh_token ( $self, $hash ) {
    my $row = $REFRESH{$hash} or return undef;
    return undef if $row->{exp} < time;
    return { binding => $row->{b}, reused => 1 } if $row->{revoked};
    $row->{revoked} = 1;
    return { binding => $row->{b} };
}
sub revoke_family ( $self, $family_id ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{family_id} // '' ) eq $family_id;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}
sub revoke_refresh_tokens_for_subject ( $self, $subject ) {
    my $n = 0;
    for my $h ( keys %REFRESH ) {
        next if $REFRESH{$h}{revoked};
        next unless ( $REFRESH{$h}{b}{subject} // '' ) eq $subject;
        $REFRESH{$h}{revoked} = 1;
        $n++;
    }
    return $n;
}

1;

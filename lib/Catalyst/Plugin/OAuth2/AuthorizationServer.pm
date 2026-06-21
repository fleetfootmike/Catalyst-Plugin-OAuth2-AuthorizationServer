package Catalyst::Plugin::OAuth2::AuthorizationServer;
use v5.36;

our $VERSION = '0.001';

=head1 NAME

Catalyst::Plugin::OAuth2::AuthorizationServer - MCP-profile OAuth 2.1
Authorization Server plugin for Catalyst

=head1 DESCRIPTION

Adds an OAuth 2.1 Authorization Server (the MCP profile: public PKCE-S256
client, C<authorization_code> + C<refresh_token> grants, Dynamic Client
Registration, and AS metadata) to a Catalyst application. The protocol engine
lives in L<Catalyst::Plugin::OAuth2::AuthorizationServer::Server>; this module
is the thin Catalyst seam (added in a later task).

=cut

1;

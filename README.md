# Catalyst::Plugin::OAuth2::AuthorizationServer

An MCP-profile OAuth 2.1 Authorization Server for Catalyst: Dynamic Client
Registration, PKCE-S256 `authorization_code` + `refresh_token` grants, RFC 8414
metadata, and HS256 JWT access tokens. Storage, authentication/consent, and
DCR rate-limiting are app-supplied hooks; the distribution carries no
application specifics.

See the module POD for configuration and the hook contract. Part of the Gobby
MCP endpoint work (sub-spec [02c]); layered alongside
`Catalyst::Plugin::JSONRPC::Server` and `Catalyst::Plugin::MCP`.

## Limitations (v1)

Refresh-token rotation revokes the presented token but does not revoke the
whole token family on a detected reuse (planned enhancement). Apps can call
`revoke_refresh_tokens_for_subject` on logout/deactivation.

Garbage-collecting abandoned Dynamic Client Registrations (clients that never
completed a token exchange) is the host app's concern — the Store has the
visibility to identify them and run the cleanup; this plugin tracks no client
usage.

## Author

Mike Whitaker <mike@altrion.org>

## License

This library is free software; you can redistribute it and/or modify it
under the terms of the Artistic License, as distributed with Perl.

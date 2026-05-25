# Changelog

All notable changes to `webpatser/resonate-token-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-25

Initial release.

### Added

- `TokenAuthPlugin`: a Resonate server plugin that lets a connection subscribe
  to private and presence channels with a token instead of the standard
  `/broadcasting/auth` HMAC round-trip. Coexists with HMAC auth: a subscribe
  that already carries an `auth` field is relayed untouched.
- Two flows: per-subscribe (`data.token` on `pusher:subscribe`) and
  pre-authenticate (`app:authenticate` event that caches the validated claims
  on the connection's state bag).
- `JwtAuthenticator`: default validator built on `firebase/php-jwt`. Supports
  HS256/HS384/HS512 (shared secret) and RS256/RS384/RS512 + ES256/ES384
  (public key). Optional `iss`/`aud` enforcement, `exp`/`nbf`/`iat` with
  configurable leeway.
- `DefaultChannelAuthorizer`: trusts a valid token for private channels,
  requires `user_id` for presence channels, honours a per-token `channels`
  claim with `fnmatch` glob patterns.
- `TokenAuthenticator` and `ChannelAuthorizer` contracts plus a `TokenClaims`
  value object: rebind either contract to plug in Sanctum, opaque tokens, or
  custom authorization rules.
- `TokenAuthServiceProvider`: merges config and binds the two defaults;
  publishes config via `vendor:publish --tag=resonate-token-auth-config`.

[Unreleased]: https://github.com/webpatser/resonate-token-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/webpatser/resonate-token-auth/releases/tag/v0.1.0

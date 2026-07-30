# Changelog

All notable changes to `webpatser/resonate-token-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-07-30

### Changed

- Widen the `webpatser/resonate` constraint to `^0.4|^0.5`. Composer treats a
  `^0.4` caret on a 0.x package as `>=0.4 <0.5`, so this package could not be
  installed next to a server running Resonate v0.5 even though the suite passes
  against it. Both major lines are now accepted.

## [0.2.1] - 2026-07-30

### Changed

- CI gates on Laravel Pint and on PHPStan at level 8, with no baseline and no
  suppressions. Plain `phpstan/phpstan` is used rather than larastan, whose
  Testbench application boot fails on an unrelated
  `webpatser/resonate` / `fledge-fiber` `Http\Client\Factory` incompatibility.
- `TokenAuthPlugin::authenticate()` and `resolveClaims()` take the already
  null-checked authenticator as a parameter instead of re-reading the nullable
  property. Behaviour is unchanged; this satisfies level 8 null safety.
- Dropped a redundant empty-string check on a `json_encode()` result that
  PHPStan proved is always non-empty.
- Added a tests and dependency-audit workflow: the suite runs on PHP 8.5 and
  `composer audit` fails the build on known-vulnerable production dependencies,
  on push to the default branch and on pull requests.

## [0.2.0] - 2026-05-25

### Added

- `Events\TokenRejected`: a Laravel event dispatched once per token rejection
  with a stable, low-cardinality `reason` (`missing_token`, `invalid_token`,
  `unauthorized_channel`) exposed as public constants. Used by
  `webpatser/resonate-pulse v0.2` to chart rejections by reason.

### Changed

- The subscribe rejection path now distinguishes between "no token supplied"
  (`missing_token`) and "token supplied but invalid" (`invalid_token`). The
  Pusher error message reflects the same distinction.

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

[Unreleased]: https://github.com/webpatser/resonate-token-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/webpatser/resonate-token-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/webpatser/resonate-token-auth/releases/tag/v0.1.0

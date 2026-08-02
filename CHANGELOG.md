# Changelog

All notable changes to `webpatser/resonate-token-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Tokens are now bound to an application.** Nothing in the token path compared
  a claim against the connection's application, while the JWT settings
  (`algorithm`, `secret`, `issuer`, `audience`) are a single global block. On a
  multi-application server one tenant's valid token was therefore accepted on
  another tenant's app key, and the plugin then synthesized *that* app's HMAC
  for it, placing the wrong user inside the wrong private and presence channels.
  A token must now carry an application-binding claim (`app_id` by default,
  remappable via `claims.app_id`) matching the connection's application id.
- **A malformed or emptied `channels` claim no longer fails open.** A `channels`
  claim that was present but empty, or present and not a list of strings,
  collapsed to an empty allow-list, which `DefaultChannelAuthorizer` read as
  "no restriction": malformed input opened *every* private and presence channel.
  An absent claim is now distinguished from a present one. A present but empty
  allow-list permits nothing, and a claim that is not a list of strings is
  rejected outright as an invalid token.
- **`exp` is required.** `firebase/php-jwt` only validates `exp` when the claim
  is present, so a token minted without one was valid forever. The default
  validator now rejects any token that does not carry one.
- **Cached claims are re-checked on every subscribe.** Claims cached by
  `app:authenticate` were validated once and then trusted for the life of the
  socket, so a connection that pre-authenticated with a short-lived token kept
  opening new subscriptions long after it expired. Expiry is now re-checked
  before each subscribe that relies on the cache.
- `JwtAuthenticator` no longer leaks its clock leeway. It assigned the global
  static `Firebase\JWT\JWT::$leeway` and never restored it, so this package's
  window silently widened the clock tolerance of every other firebase/php-jwt
  consumer in the process. The previous value is now restored, including when
  decoding throws.

### Added

- `require_app_claim` config flag (default `true`, env
  `RESONATE_TOKEN_AUTH_REQUIRE_APP_CLAIM`). It decides only whether a token
  carrying *no* application binding is accepted; a claim naming a different
  application is rejected either way. Set it to `false` to migrate issuers that
  do not mint the claim yet, then back to `true`. See the README for the
  rollout steps.
- `claims.app_id` config key (default `app_id`, env
  `RESONATE_TOKEN_AUTH_APP_ID_CLAIM`) to remap the binding claim.
- `TokenRejected::APPLICATION_MISMATCH` (`application_mismatch`) and
  `TokenRejected::EXPIRED_TOKEN` (`expired_token`) reason constants, so metrics
  consumers can bucket cross-tenant attempts and stale pre-auth separately from
  `invalid_token`.
- `TokenClaims::expiresAt()` and `TokenClaims::hasExpired()`.

### Changed

- **API:** `TokenClaims::$channels` and `TokenClaims::channels()` are now
  `list<string>|null` instead of `list<string>`, and the constructor default is
  `null` rather than `[]`. `null` means "the token carried no allow-list, so no
  token-level restriction"; `[]` now means "an allow-list that permits nothing".
  A custom `ChannelAuthorizer` that treated `[] === "no restriction"` must be
  updated to check for `null`.
- **Behaviour:** upgrading rejects tokens that carry no application-binding
  claim until issuers are updated or `require_app_claim` is set to `false`, and
  rejects tokens minted without `exp` outright.
- A custom `TokenAuthenticator` must carry `exp` and the application-binding
  claim through into the `TokenClaims` raw bag; claims with no readable `exp`
  are treated as expired rather than as never expiring.

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

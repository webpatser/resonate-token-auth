# Changelog

All notable changes to `webpatser/resonate-token-auth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A connection can no longer switch identity with a second `app:authenticate`. A token for a different subject is rejected with a `pusher:error` (reason `already_authenticated`) while the cached claims are still valid, instead of replying `app:authenticated` with a user id that differs from the cached claims. Re-authenticating with a token for the same subject (a refresh), or with any valid token once the cached claims have expired, still replaces the claims as before.

### Added

- Opt-in `pin_identity` config (`RESONATE_TOKEN_AUTH_PIN_IDENTITY`, default `false`): rejects per-subscribe tokens whose subject differs from the connection's pre-authenticated identity (reason `identity_mismatch`).

## [0.7.0] - 2026-09-23

### Changed

- Versioning now tracks `webpatser/resonate`'s minor version: `0.7.x` targets resonate 0.7.
- Require `webpatser/resonate` `^0.7` (was `^0.4|^0.5|^0.6|^0.7`), dropping support for resonate 0.6 and earlier.

## [0.3.3] - 2026-09-23

### Changed

- Support `webpatser/resonate` v0.7.

## [0.3.2] - 2026-09-02

### Changed

- Verified against `webpatser/resonate` v0.6.1 and `webpatser/fledge-fiber` v13.30.1.0. No code change: this package holds no Redis connection of its own and touches no API the server release moved.

## [0.3.1] - 2026-08-02

### Fixed

- Allow `webpatser/resonate` v0.6. The constraint excluded it, so this package could not be installed alongside the current server release. Verified against v0.6.0.

## [0.3.0] - 2026-08-02

This release rejects tokens that earlier versions accepted. Read
[Upgrading](#upgrading) before deploying it.

### Security

- Bind tokens to an application: a token must carry a claim naming the
  application it is presented on, or one tenant's token is valid on every
  tenant's app key.
- Deny on a `channels` claim that is present but empty, and reject one that is
  not a list of strings. Both previously collapsed to "no restriction" and
  opened every private and presence channel.
- Require `exp`. `firebase/php-jwt` validates the value only when the claim is
  present, so a token minted without one never expired.
- Re-check cached pre-authentication claims against their `exp` on every
  subscribe, so a socket cannot outlive the token that authenticated it.
- Restore `Firebase\JWT\JWT::$leeway` after decoding. Assigning the global
  static and walking away widened the clock tolerance of every other
  firebase/php-jwt consumer in the process.

### Added

- `require_app_claim` config flag (default `true`, env
  `RESONATE_TOKEN_AUTH_REQUIRE_APP_CLAIM`): whether a token carrying no
  application binding is accepted. A mismatching claim is rejected either way.
- `claims.app_id` config key (default `app_id`, env
  `RESONATE_TOKEN_AUTH_APP_ID_CLAIM`) to remap the binding claim.
- `TokenRejected::APPLICATION_MISMATCH` (`application_mismatch`) and
  `TokenRejected::EXPIRED_TOKEN` (`expired_token`) reason constants.
- `TokenClaims::expiresAt()` and `TokenClaims::hasExpired()`.

### Changed

- `TokenClaims::$channels` and `TokenClaims::channels()` are `list<string>|null`
  instead of `list<string>`, and the constructor default is `null` rather than
  `[]`.
- A custom `TokenAuthenticator` must carry `exp` and the binding claim through
  into the `TokenClaims` raw bag; claims with no readable `exp` count as
  expired.

### Upgrading

Every item below can reject a token that 0.2.2 accepted. Nothing here is opt-in
except the migration switch.

**Tokens must name their application.** The binding claim is `app_id` by
default (remap with `claims.app_id`) and its value is matched against the
connection's Resonate application id, the `app_id` in `config/reverb.php`, not
the app key. A claim naming a different application is always fatal and reports
`application_mismatch`. `require_app_claim` (default `true`) decides only what
happens to a token carrying no binding claim at all; it never forgives a
mismatch. The check runs on `pusher:subscribe` and on `app:authenticate`.

**`exp` is mandatory.** A token without one is rejected as invalid rather than
treated as eternal.

**An empty `channels` claim denies everything.** `channels()` now returns
`null` when the token carried no allow-list and a list when it did, so `[]` is
an allow-list that permits nothing. A custom `ChannelAuthorizer` that read `[]`
as "no restriction" must test for `null` instead, or it will keep failing open.
A `channels` claim that is not a list of strings is now rejected as an invalid
token instead of being coerced to `[]`.

**Cached claims go stale.** Claims cached by `app:authenticate` are re-checked
against `exp` (with the configured `leeway`) before every subscribe that relies
on them, and a stale cache reports `expired_token`. Existing subscriptions are
untouched: the client either sends a fresh token with the next subscribe, which
overrides the cache, or reconnects and pre-authenticates again.

What token issuers need to change:

1. Add the binding claim: `'app_id' => config('reverb.apps.apps.0.app_id')`.
2. Add `exp` to every token, kept short (minutes, not days).
3. Send `channels` only when the token should be limited to particular
   channels, and never send it empty. Omit it for no token-level restriction.
4. Carry `exp` and the binding claim into `TokenClaims::$raw` in any custom
   `TokenAuthenticator`.

To roll this out without downtime, set
`RESONATE_TOKEN_AUTH_REQUIRE_APP_CLAIM=false` and deploy, update the issuers,
let the old tokens expire, then set it back to `true`.

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

[Unreleased]: https://github.com/webpatser/resonate-token-auth/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/webpatser/resonate-token-auth/compare/v0.3.2...v0.3.3
[0.3.0]: https://github.com/webpatser/resonate-token-auth/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/webpatser/resonate-token-auth/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/webpatser/resonate-token-auth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/webpatser/resonate-token-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/webpatser/resonate-token-auth/releases/tag/v0.1.0

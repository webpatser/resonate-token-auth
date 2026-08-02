# Resonate Token Auth

Token-based subscription auth for [Resonate](https://github.com/webpatser/resonate). Skips the `/broadcasting/auth` HMAC round-trip for clients that have a token (JWT by default, anything via a pluggable validator) instead of a session cookie.

## The problem it solves

Resonate authenticates private and presence channel subscriptions the Pusher way: the browser POSTs `socket_id` + `channel` to your Laravel `/broadcasting/auth` endpoint, the endpoint reads the session, and returns an HMAC signature the client carries in `pusher:subscribe`. That works for browsers; it does not work as cleanly for:

- mobile clients that do not carry a session cookie,
- server-to-server bots that need to subscribe,
- federated apps where the user identity lives in an OAuth or JWT issuer.

This package lets a connection present a token directly to Resonate. The plugin validates it, derives the user identity from its claims, and synthesizes the HMAC signature the standard subscribe path already knows how to verify, so the rest of Resonate runs unchanged.

## How it works

### One verify path, two ways to feed it

```
client                       TokenAuthPlugin                 Resonate core
──────                       ───────────────                 ─────────────
pusher:subscribe       ─►    validate token  ─►              EventHandler::subscribe
{channel, token}             authorize claim                   verify HMAC (passes)
                             synthesize HMAC                   member_added
                             hand off                          subscription_succeeded
```

When a `pusher:subscribe` arrives with a `token` field instead of an `auth` field, the plugin:

1. validates the token via the configured `TokenAuthenticator` (JWT by default),
2. checks that the token is bound to the application it was presented on,
3. asks the `ChannelAuthorizer` whether the claims may subscribe to this channel,
4. for presence channels, builds the `channel_data` from the token's `user_id` (and optional `user_info`),
5. computes the same HMAC signature `/broadcasting/auth` would have returned, using the app's secret,
6. hands the rewritten payload to `EventHandler::handle()` so the standard subscribe path runs.

Because the plugin signs with the same secret the verifier checks against, the standard `InteractsWithPrivateChannels::verify()` accepts the synthesized signature without ever knowing the plugin was involved. The `subscription_succeeded` frame, the presence `member_added` broadcast, the plugin lifecycle hooks: all of it runs.

### Per-subscribe or pre-authenticated

The plugin supports two equivalent flows. Pick whichever fits your client.

**Per-subscribe (stateless).** Include the token on every subscribe:

```json
{"event": "pusher:subscribe", "data": {"channel": "presence-chat.42", "token": "..."}}
```

**Pre-authenticated (cached).** Authenticate once, then subscribe without a token:

```json
{"event": "app:authenticate", "data": {"token": "..."}}
```

The plugin replies with `app:authenticated` and caches the validated claims on the connection. Subsequent subscribes need no token:

```json
{"event": "pusher:subscribe", "data": {"channel": "presence-chat.42"}}
```

The two flows coexist. A per-subscribe token always overrides the cached claims, so a stateless client never depends on connection-bound state.

Cached claims are re-checked against their `exp` on every subscribe. A connection that pre-authenticated with a five minute token stops being able to open new subscriptions once those five minutes are up, instead of coasting for the life of the socket. Existing subscriptions are left alone; the client either sends a fresh token with the next subscribe (which overrides the stale cache) or reconnects and pre-authenticates again.

### Tokens are bound to one application

Resonate can serve several applications from one process, each with its own key and secret, while the JWT settings here are a single global block. Without a binding claim a token minted for tenant A verifies just as well on tenant B's app key, and the plugin would then synthesize B's HMAC for it: A's user lands inside B's private and presence channels.

So every token has to name the application it was minted for, in an `app_id` claim by default:

```json
{"sub": "42", "app_id": "your-app-id", "exp": 1800000000}
```

The value is matched against the connection's Resonate application id (`app_id` in `config/reverb.php`, not the app *key*). A token naming a different application is always rejected, with a `pusher:error` and a `TokenRejected` event carrying reason `application_mismatch`.

**Migrating existing issuers.** Requiring the claim is the default, so an upgrade rejects tokens minted before you started sending it. To roll out without downtime:

1. Set `RESONATE_TOKEN_AUTH_REQUIRE_APP_CLAIM=false` (or `'require_app_claim' => false` in the published config) and deploy. Tokens without the claim keep working; tokens naming the *wrong* application are still rejected, because the switch only forgives a missing claim, never a mismatch.
2. Add `'app_id' => config('reverb.apps.apps.0.app_id')` to whatever mints your tokens, and let the old ones expire.
3. Put the switch back to `true`.

Single-application servers are not exposed to the cross-tenant problem, but the claim is still required by default there: it costs one line at the issuer and it means adding a second app later cannot quietly open a hole.

### Coexists with HMAC

A `pusher:subscribe` that already carries an `auth` field is relayed untouched: the standard `/broadcasting/auth` flow runs. Browser clients with cookies keep working; token clients use the new path. They share the same server, the same channels, the same presence semantics.

## Installation

```bash
composer require webpatser/resonate-token-auth
```

Publish the config if you want to change defaults:

```bash
php artisan vendor:publish --tag=resonate-token-auth-config
```

## Registering the plugin

```php
// config/reverb.php
'servers' => [
    'reverb' => [
        // ...
        'plugins' => [
            \Webpatser\ResonateTokenAuth\TokenAuthPlugin::class,
        ],
    ],
],
```

Restart Resonate (`php artisan resonate:start`, or `resonate:reload` for a zero-downtime swap).

## Configuration

```dotenv
RESONATE_TOKEN_AUTH_ALG=HS256
RESONATE_TOKEN_AUTH_SECRET=your-shared-jwt-secret
# RESONATE_TOKEN_AUTH_PUBLIC_KEY (PEM)        # for RS*/ES* algorithms
# RESONATE_TOKEN_AUTH_ISSUER=https://your.app
# RESONATE_TOKEN_AUTH_AUDIENCE=resonate
```

| Key | Default | Purpose |
|-----|---------|---------|
| `algorithm` | `HS256` | JWT signing algorithm. HS256/384/512 (shared secret) or RS256/384/512, ES256/384 (public key). |
| `secret` | `null` | Shared secret for HS* algorithms. |
| `public_key` | `null` | PEM-encoded public key for RS*/ES* algorithms. |
| `issuer` | `null` | When set, the token's `iss` claim must match. |
| `audience` | `null` | When set, the token's `aud` claim must match (string or list). |
| `leeway` | `30` | Seconds of clock skew tolerated on `exp`/`nbf`/`iat`, and when re-checking cached claims. |
| `require_app_claim` | `true` | Whether a token with no application-binding claim is accepted. A *mismatching* claim is rejected either way. |
| `claims.user_id` | `sub` | Which JWT claim is the user id. |
| `claims.user_info` | `user_info` | Which claim holds optional presence user info. |
| `claims.channels` | `channels` | Which claim, if present, lists allowed channels (glob patterns). |
| `claims.app_id` | `app_id` | Which claim carries the application binding. |

### Claim rules the default validator enforces

| Claim | Rule |
|-------|------|
| `exp` | **Required.** A token minted without one is rejected. `firebase/php-jwt` only validates the value when the claim is present, so accepting a token without it meant accepting a token that never expires. |
| `channels` | Optional, but if present it must be a list of strings. A non-list (`"private-foo"`, `5`, an object, a list with junk in it) is rejected outright rather than coerced. |
| `channels: []` | Present but empty is an allow-list that permits **nothing**, so every private and presence subscribe is denied. Only an *absent* `channels` claim means "no token-level restriction". |
| `app_id` | Required unless `require_app_claim` is false; must equal the connection's application id. |

## Plugging in another token format

The default validator is JWT. To accept Sanctum tokens, opaque tokens against an introspection endpoint, or anything else, implement `TokenAuthenticator` and bind it:

```php
// AppServiceProvider::register()
$this->app->bind(
    \Webpatser\ResonateTokenAuth\Contracts\TokenAuthenticator::class,
    \App\Resonate\SanctumTokenAuthenticator::class,
);
```

`ChannelAuthorizer` is the same: bind your own for tenant rules, role checks, or external lookups.

## Issuing tokens

A short Laravel helper to mint a JWT this plugin accepts (with `firebase/php-jwt`):

```php
use Firebase\JWT\JWT;

return JWT::encode([
    'iss' => config('app.url'),
    'aud' => 'resonate',
    'sub' => (string) $user->id,
    'app_id' => config('reverb.apps.apps.0.app_id'),
    'user_info' => ['name' => $user->name],
    'channels' => ['presence-chat.*', 'private-user.'.$user->id],
    'iat' => time(),
    'exp' => time() + 300,
], config('resonate-token-auth.secret'), 'HS256');
```

`exp` is mandatory, and `app_id` must match the application the client connects to. Omit `channels` entirely when the token should not be limited to particular channels; sending it empty denies everything.

Mobile clients fetch this on login and pass it in `pusher:subscribe.data.token`.

## Security notes

- **Bearer tokens.** Anyone holding a valid token can subscribe. Serve tokens over TLS, keep `exp` short (minutes, not days), and treat the signing key as a server secret.
- **No revocation.** A valid, unexpired JWT cannot be revoked by this plugin. Use short lifetimes; if revocation matters, bind a custom `TokenAuthenticator` that checks a deny list.
- **One identity per connection.** The first valid `app:authenticate` binds the cached claims; subsequent `app:authenticate` events are ignored so a long-lived connection cannot silently change identity. That holds after the cached claims expire too: the connection cannot re-bind to a different identity, it can only present a fresh token per subscribe or reconnect.
- **One application per token.** A token is only valid on the application named in its binding claim. See "Tokens are bound to one application" above.
- **Custom authenticators.** The application binding and the cached-claim expiry check both read the `TokenClaims` raw claim bag, so a custom `TokenAuthenticator` must carry `exp` and the app claim through into `raw`. Claims with no readable `exp` are treated as expired rather than as eternal.
- **Public channels are untouched.** The plugin only authorizes `private-*` and `presence-*` subscribes; public channels are relayed.

## Requirements

- PHP 8.5+
- Resonate 0.4+

## Testing

```bash
composer test
```

The suite does not need Redis or any external service.

## License

MIT. See [LICENSE](LICENSE).

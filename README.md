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
2. asks the `ChannelAuthorizer` whether the claims may subscribe to this channel,
3. for presence channels, builds the `channel_data` from the token's `user_id` (and optional `user_info`),
4. computes the same HMAC signature `/broadcasting/auth` would have returned, using the app's secret,
5. hands the rewritten payload to `EventHandler::handle()` so the standard subscribe path runs.

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
| `leeway` | `30` | Seconds of clock skew tolerated on `exp`/`nbf`/`iat`. |
| `claims.user_id` | `sub` | Which JWT claim is the user id. |
| `claims.user_info` | `user_info` | Which claim holds optional presence user info. |
| `claims.channels` | `channels` | Which claim, if present, lists allowed channels (glob patterns). |

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
    'user_info' => ['name' => $user->name],
    'channels' => ['presence-chat.*', 'private-user.'.$user->id],
    'iat' => time(),
    'exp' => time() + 300,
], config('resonate-token-auth.secret'), 'HS256');
```

Mobile clients fetch this on login and pass it in `pusher:subscribe.data.token`.

## Security notes

- **Bearer tokens.** Anyone holding a valid token can subscribe. Serve tokens over TLS, keep `exp` short (minutes, not days), and treat the signing key as a server secret.
- **No revocation.** A valid, unexpired JWT cannot be revoked by this plugin. Use short lifetimes; if revocation matters, bind a custom `TokenAuthenticator` that checks a deny list.
- **One identity per connection.** The first valid `app:authenticate` binds the cached claims; subsequent `app:authenticate` events are ignored so a long-lived connection cannot silently change identity.
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

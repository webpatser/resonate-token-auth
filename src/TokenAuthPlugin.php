<?php

namespace Webpatser\ResonateTokenAuth;

use Webpatser\Resonate\Contracts\Connection;
use Webpatser\Resonate\Plugins\Contracts\MessageInterceptor;
use Webpatser\Resonate\Plugins\Contracts\ServerPlugin;
use Webpatser\Resonate\Plugins\MessageDisposition;
use Webpatser\Resonate\Plugins\PluginContext;
use Webpatser\Resonate\Protocols\Pusher\EventHandler;
use Webpatser\ResonateTokenAuth\Contracts\ChannelAuthorizer;
use Webpatser\ResonateTokenAuth\Contracts\TokenAuthenticator;
use Webpatser\ResonateTokenAuth\Events\TokenRejected;

/**
 * Lets a connection subscribe to private and presence channels with a token
 * instead of the standard `/broadcasting/auth` HMAC round-trip.
 *
 * Two flows are supported:
 *
 * - **Per-subscribe:** `pusher:subscribe` carries a `token` field in `data`.
 *   The plugin validates it, synthesizes the HMAC signature the standard
 *   subscribe path expects, and hands off to {@see EventHandler}.
 *
 * - **Pre-authenticate:** the client first sends `app:authenticate` with a
 *   token; the validated claims are cached on the connection state bag.
 *   Subsequent subscribes carry no token and the plugin uses the cached
 *   claims.
 *
 * The plugin **complements** standard HMAC auth: a subscribe that already
 * carries an `auth` field is relayed untouched. Browser clients with cookies
 * and token-bearing clients coexist on the same server.
 *
 * Every token, on either flow, must also be bound to the application it is
 * presented on (see {@see boundToApplication()}), and cached pre-auth claims
 * are re-checked against their `exp` on every subscribe so a connection cannot
 * outlive the token that authenticated it.
 */
class TokenAuthPlugin implements MessageInterceptor, ServerPlugin
{
    /**
     * The server API surface handed in at boot.
     */
    protected PluginContext $context;

    /**
     * The token validator. Resolved from the container at boot.
     */
    protected ?TokenAuthenticator $authenticator = null;

    /**
     * The channel authorizer. Resolved from the container at boot.
     */
    protected ?ChannelAuthorizer $authorizer = null;

    /**
     * Which claim carries the application binding.
     */
    protected string $appClaim = 'app_id';

    /**
     * Whether a token must carry the application-binding claim at all.
     */
    protected bool $requireAppClaim = true;

    /**
     * Clock skew, in seconds, allowed when re-checking cached claims.
     */
    protected int $leeway = 30;

    /**
     * Whether a per-subscribe token must carry the same subject as the
     * connection's pre-authenticated identity.
     */
    protected bool $pinIdentity = false;

    /**
     * Boot the plugin: resolve the authenticator and authorizer, and read the
     * settings the plugin itself enforces (application binding, leeway).
     */
    public function boot(PluginContext $context): void
    {
        $this->context = $context;
        $this->authenticator = app(TokenAuthenticator::class);
        $this->authorizer = app(ChannelAuthorizer::class);

        $config = (array) config('resonate-token-auth', []);
        $claims = (array) ($config['claims'] ?? []);

        $this->appClaim = (string) ($claims['app_id'] ?? 'app_id');
        $this->requireAppClaim = (bool) ($config['require_app_claim'] ?? true);
        $this->leeway = (int) ($config['leeway'] ?? 30);
        $this->pinIdentity = (bool) ($config['pin_identity'] ?? false);
    }

    /**
     * Intercept inbound messages, authorize token-based subscribes, and relay
     * everything else.
     *
     * @param  array{event?:mixed,channel?:mixed,data?:mixed}  $event
     */
    public function onMessage(Connection $from, array $event): MessageDisposition
    {
        if ($this->authenticator === null || $this->authorizer === null) {
            return MessageDisposition::Relay;
        }

        $name = $event['event'] ?? null;

        if (! is_string($name)) {
            return MessageDisposition::Relay;
        }

        if ($name === 'app:authenticate') {
            return $this->authenticate($this->authenticator, $from, (array) ($event['data'] ?? []));
        }

        if ($name !== 'pusher:subscribe') {
            return MessageDisposition::Relay;
        }

        $data = (array) ($event['data'] ?? []);
        $channel = (string) ($data['channel'] ?? '');

        if (! $this->isProtectedChannel($channel)) {
            return MessageDisposition::Relay;
        }

        // A subscribe that already carries an HMAC auth field is a standard
        // Pusher flow: don't second-guess it, let the standard verify run.
        if (isset($data['auth']) && $data['auth'] !== '') {
            return MessageDisposition::Relay;
        }

        $tokenSupplied = isset($data['token']) && is_string($data['token']) && $data['token'] !== '';
        $claims = $this->resolveClaims($this->authenticator, $from, $data);

        if ($claims === null) {
            $reason = $tokenSupplied ? TokenRejected::INVALID_TOKEN : TokenRejected::MISSING_TOKEN;
            $message = $tokenSupplied ? 'Invalid token' : 'Token required for protected channel';

            $this->reject($from, $message, $reason);

            return MessageDisposition::Rejected;
        }

        // Cached pre-auth claims are only validated once, at `app:authenticate`
        // time, and then live as long as the socket does. A connection that
        // authenticated with a five minute token could therefore keep opening
        // new subscriptions for hours, so the expiry is re-checked here, on
        // every subscribe that leans on the cache. A token supplied with this
        // very subscribe was just validated, expiry included.
        if (! $tokenSupplied && $claims->hasExpired($this->leeway)) {
            $this->reject($from, 'Token expired, re-authenticate', TokenRejected::EXPIRED_TOKEN);

            return MessageDisposition::Rejected;
        }

        if (! $this->boundToApplication($claims, $from)) {
            $this->reject($from, 'Token not valid for this application', TokenRejected::APPLICATION_MISMATCH);

            return MessageDisposition::Rejected;
        }

        if ($tokenSupplied && $this->pinIdentity && ! $this->matchesPreAuthIdentity($claims, $from)) {
            $this->reject($from, 'Token subject does not match the authenticated identity', TokenRejected::IDENTITY_MISMATCH);

            return MessageDisposition::Rejected;
        }

        if (! $this->authorizer->authorize($claims, $channel)) {
            $this->reject($from, 'Token not authorized for channel', TokenRejected::UNAUTHORIZED_CHANNEL);

            return MessageDisposition::Rejected;
        }

        $this->dispatchAuthorizedSubscribe($from, $channel, $claims);

        return MessageDisposition::Handled;
    }

    /**
     * Pre-authenticate a connection from an `app:authenticate` event.
     *
     * @param  array<string, mixed>  $data
     */
    protected function authenticate(TokenAuthenticator $authenticator, Connection $from, array $data): MessageDisposition
    {
        $token = (string) ($data['token'] ?? '');

        if ($token === '') {
            $this->reject($from, 'Missing token', TokenRejected::MISSING_TOKEN);

            return MessageDisposition::Rejected;
        }

        $claims = $authenticator->validate($token);

        if ($claims === null) {
            $this->reject($from, 'Invalid token', TokenRejected::INVALID_TOKEN);

            return MessageDisposition::Rejected;
        }

        if (! $this->boundToApplication($claims, $from)) {
            $this->reject($from, 'Token not valid for this application', TokenRejected::APPLICATION_MISMATCH);

            return MessageDisposition::Rejected;
        }

        // A connection may re-authenticate to refresh its token (same subject)
        // or once its cached claims have expired, which is exactly what the
        // server tells clients to do. Switching to a different subject while
        // the cached claims are still valid is refused, so a live connection
        // cannot change identity.
        $cached = $from->state('token.claims');

        if (
            $cached instanceof TokenClaims
            && ! $cached->hasExpired($this->leeway)
            && ! hash_equals((string) $cached->userId(), (string) $claims->userId())
        ) {
            $this->reject($from, 'Connection is already authenticated', TokenRejected::ALREADY_AUTHENTICATED);

            return MessageDisposition::Rejected;
        }

        $from->setState('token.claims', $claims);

        $this->context->sendTo($from, 'app:authenticated', [
            'user_id' => $claims->userId(),
        ]);

        return MessageDisposition::Handled;
    }

    /**
     * Resolve the claims to use for a subscribe: per-subscribe token first,
     * pre-auth claims second.
     *
     * @param  array<string, mixed>  $data
     */
    protected function resolveClaims(TokenAuthenticator $authenticator, Connection $from, array $data): ?TokenClaims
    {
        if (isset($data['token']) && is_string($data['token']) && $data['token'] !== '') {
            return $authenticator->validate($data['token']);
        }

        $cached = $from->state('token.claims');

        return $cached instanceof TokenClaims ? $cached : null;
    }

    /**
     * Synthesize the HMAC signature and hand the subscribe off to the
     * standard {@see EventHandler} path.
     */
    protected function dispatchAuthorizedSubscribe(Connection $from, string $channel, TokenClaims $claims): void
    {
        $channelData = null;

        if (str_starts_with($channel, 'presence-')) {
            // Always include user_info so downstream presence aggregation
            // sees the key (null is fine; a missing key is not).
            $channelData = json_encode([
                'user_id' => $claims->userId(),
                'user_info' => $claims->userInfo(),
            ], JSON_THROW_ON_ERROR);
        }

        $signaturePayload = $from->id().':'.$channel;

        if ($channelData !== null) {
            $signaturePayload .= ':'.$channelData;
        }

        $auth = $from->app()->key().':'.hash_hmac(
            'sha256',
            $signaturePayload,
            $from->app()->secret(),
        );

        app(EventHandler::class)->handle($from, 'pusher:subscribe', [
            'channel' => $channel,
            'auth' => $auth,
            'channel_data' => $channelData,
        ]);
    }

    /**
     * Determine whether the claims are bound to the connection's application.
     *
     * Resonate can serve many applications from one process, each with its own
     * key and secret, while the JWT settings here (algorithm, secret, issuer,
     * audience) are a single global block. Without this check a token minted
     * for tenant A is a valid token *everywhere*: presented on tenant B's app
     * key it validates against the same secret, and the plugin then synthesizes
     * B's HMAC for it, so A's user lands inside B's private and presence
     * channels. Nothing else in the path ever looks at which app is in play.
     *
     * A claim that is present and does not match is always fatal.
     * `require_app_claim` only decides whether a token carrying no binding at
     * all is still accepted, which is the migration switch for issuers minting
     * tokens from before this was enforced. It never permits a mismatch.
     */
    protected function boundToApplication(TokenClaims $claims, Connection $from): bool
    {
        $claimed = $claims->claim($this->appClaim);

        if ($claimed === null) {
            return ! $this->requireAppClaim;
        }

        if (! is_string($claimed) && ! is_int($claimed)) {
            return false;
        }

        return (string) $claimed === $from->app()->id();
    }

    /**
     * Determine whether a per-subscribe token's subject equals the identity the
     * connection pre-authenticated as. A connection that never pre-authenticated
     * has no identity to pin, so any valid token passes.
     */
    protected function matchesPreAuthIdentity(TokenClaims $claims, Connection $from): bool
    {
        $cached = $from->state('token.claims');

        if (! $cached instanceof TokenClaims) {
            return true;
        }

        return hash_equals((string) $cached->userId(), (string) $claims->userId());
    }

    /**
     * Determine whether a channel needs auth at all.
     */
    protected function isProtectedChannel(string $channel): bool
    {
        return str_starts_with($channel, 'private-')
            || str_starts_with($channel, 'presence-');
    }

    /**
     * Send a Pusher-format error frame; the connection itself stays open so
     * the client can retry with a fresh token.
     */
    protected function reject(Connection $from, string $message, string $reason): void
    {
        $this->context->sendTo($from, 'pusher:error', [
            'code' => 4009,
            'message' => $message,
        ]);

        TokenRejected::dispatch($reason);
    }
}

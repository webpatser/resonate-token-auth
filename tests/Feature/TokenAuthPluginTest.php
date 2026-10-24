<?php

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Event;
use Webpatser\Resonate\Contracts\ApplicationProvider;
use Webpatser\Resonate\Plugins\MessageDisposition;
use Webpatser\Resonate\Plugins\PluginContext;
use Webpatser\Resonate\Protocols\Pusher\Contracts\ChannelManager;
use Webpatser\ResonateTokenAuth\Events\TokenRejected;
use Webpatser\ResonateTokenAuth\Tests\Support\FakeConnection;
use Webpatser\ResonateTokenAuth\TokenAuthPlugin;
use Webpatser\ResonateTokenAuth\TokenClaims;

beforeEach(function () {
    $this->app->instance('app-fixture', app(ApplicationProvider::class)->findById('app-id'));
});

function bootPlugin(): TokenAuthPlugin
{
    $plugin = new TokenAuthPlugin;
    $plugin->boot(new PluginContext(app(ChannelManager::class)));

    return $plugin;
}

/**
 * Mint a token for the test application.
 *
 * `app_id` is part of the baseline because the plugin now requires every token
 * to say which application it was minted for; pass it explicitly to override.
 */
function makeToken(array $claims = []): string
{
    return JWT::encode(
        $claims + ['sub' => 'u-1', 'app_id' => 'app-id', 'iat' => time(), 'exp' => time() + 60],
        'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256',
        'HS256',
    );
}

/**
 * Mint an otherwise valid token that names no application at all, the shape
 * every issuer produced before the binding claim existed.
 */
function makeUnboundToken(array $claims = []): string
{
    return JWT::encode(
        $claims + ['sub' => 'u-1', 'iat' => time(), 'exp' => time() + 60],
        'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256',
        'HS256',
    );
}

function makeConnection(string $socketId = 'sock-1'): FakeConnection
{
    return new FakeConnection($socketId, app('app-fixture'));
}

it('subscribes a private channel from a per-subscribe token', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken()],
    ]);

    $channel = app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing');

    expect($disposition)->toBe(MessageDisposition::Handled)
        ->and($channel)->not->toBeNull()
        ->and($channel->connections())->toHaveCount(1)
        ->and($connection->received('pusher_internal:subscription_succeeded'))->toBeTrue();
});

it('subscribes a presence channel with channel_data derived from claims', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => [
            'channel' => 'presence-room',
            'token' => makeToken(['sub' => 'u-7', 'user_info' => ['name' => 'Alice']]),
        ],
    ]);

    $channel = app(ChannelManager::class)->for(app('app-fixture'))->find('presence-room');
    $member = $channel->connections()[$connection->id()] ?? null;

    expect($member)->not->toBeNull()
        ->and($member->data('user_id'))->toBe('u-7')
        ->and($member->data('user_info'))->toBe(['name' => 'Alice']);
});

it('rejects a subscribe with an invalid token', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => 'not.a.real.jwt'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::INVALID_TOKEN);
});

it('rejects a subscribe with a token not authorized for the channel', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => [
            'channel' => 'private-secrets',
            'token' => makeToken(['channels' => ['private-public.*']]),
        ],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::UNAUTHORIZED_CHANNEL);
});

it('relays a subscribe that already carries an HMAC auth field', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-foo', 'auth' => 'app-key:somehmac'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Relay)
        ->and($connection->messages)->toBe([]);
});

it('relays a public channel subscribe with no token', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'updates'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Relay)
        ->and($connection->messages)->toBe([]);
});

it('caches claims on pre-authentication and lets a tokenless subscribe through', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $authDisposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-9'])],
    ]);

    expect($authDisposition)->toBe(MessageDisposition::Handled)
        ->and($connection->received('app:authenticated'))->toBeTrue()
        ->and($connection->state('token.claims'))->toBeInstanceOf(TokenClaims::class);

    $subscribeDisposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'presence-room'],
    ]);

    $channel = app(ChannelManager::class)->for(app('app-fixture'))->find('presence-room');
    $member = $channel->connections()[$connection->id()] ?? null;

    expect($subscribeDisposition)->toBe(MessageDisposition::Handled)
        ->and($member?->data('user_id'))->toBe('u-9');
});

it('rejects pre-authentication with an invalid token', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => 'not-a-jwt'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and($connection->state('token.claims'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::INVALID_TOKEN);
});

it('rejects a tokenless subscribe when no pre-auth happened', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-foo'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::MISSING_TOKEN);
});

it('does not change identity on a second pre-authenticate', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-first'])],
    ]);

    $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-second'])],
    ]);

    $claims = $connection->state('token.claims');

    expect($claims->userId())->toBe('u-first');
});

it('rejects a different-subject pre-authenticate while the cached claims are valid', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-first'])],
    ]);
    $connection->messages = [];

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-second'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and($connection->received('app:authenticated'))->toBeFalse()
        ->and($connection->state('token.claims')->userId())->toBe('u-first');

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::ALREADY_AUTHENTICATED);
});

it('rejects a subscribe with a token minted for another application', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    // A valid token for tenant "other-app", replayed on this app's key. The
    // JWT settings are global, so it verifies; only the binding claim stops it.
    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken(['app_id' => 'other-app'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::APPLICATION_MISMATCH);
});

it('rejects a pre-authenticate with a token minted for another application', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['app_id' => 'other-app'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('app:authenticated'))->toBeFalse()
        ->and($connection->state('token.claims'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::APPLICATION_MISMATCH);
});

it('rejects a token carrying no application binding by default', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeUnboundToken()],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::APPLICATION_MISMATCH);
});

it('accepts a token carrying no application binding when the requirement is off', function () {
    config()->set('resonate-token-auth.require_app_claim', false);

    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeUnboundToken()],
    ]);

    expect($disposition)->toBe(MessageDisposition::Handled)
        ->and($connection->received('pusher_internal:subscription_succeeded'))->toBeTrue();
});

it('still rejects a mismatching application binding when the requirement is off', function () {
    // The switch only forgives a missing claim. A claim naming another tenant
    // is always fatal, otherwise the escape hatch would reopen the hole.
    config()->set('resonate-token-auth.require_app_claim', false);

    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken(['app_id' => 'other-app'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected);

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::APPLICATION_MISMATCH);
});

it('rejects a subscribe on cached claims whose token has expired', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    // Pre-auth claims live as long as the socket does, so a short-lived token
    // used to buy unlimited subscribes for the life of the connection.
    $connection->setState('token.claims', new TokenClaims(
        userId: 'u-1',
        raw: ['exp' => time() - 3600, 'app_id' => 'app-id'],
    ));

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::EXPIRED_TOKEN);
});

it('allows a subscribe on cached claims that are still live', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $connection->setState('token.claims', new TokenClaims(
        userId: 'u-1',
        raw: ['exp' => time() + 300, 'app_id' => 'app-id'],
    ));

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Handled);
});

it('lets a fresh per-subscribe token override expired cached claims', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $connection->setState('token.claims', new TokenClaims(
        userId: 'u-1',
        raw: ['exp' => time() - 3600, 'app_id' => 'app-id'],
    ));

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken()],
    ]);

    expect($disposition)->toBe(MessageDisposition::Handled)
        ->and($connection->received('pusher_internal:subscription_succeeded'))->toBeTrue();
});

it('rejects a subscribe whose token carries an emptied channels claim', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    // End to end: an empty allow-list used to read as "no restriction" and
    // opened every private and presence channel on the server.
    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken(['channels' => []])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::UNAUTHORIZED_CHANNEL);
});

it('rejects a subscribe whose token carries a malformed channels claim', function () {
    Event::fake([TokenRejected::class]);
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => makeToken(['channels' => 'private-billing'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();

    Event::assertDispatched(TokenRejected::class, fn (TokenRejected $e) => $e->reason === TokenRejected::INVALID_TOKEN);
});

it('relays unrelated events untouched', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, ['event' => 'pusher:ping', 'data' => []]);

    expect($disposition)->toBe(MessageDisposition::Relay);
});

it('accepts a second pre-authenticate with the same subject as a token refresh', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-1', 'exp' => time() + 60])],
    ]);
    $connection->messages = [];

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-1', 'exp' => time() + 600])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Handled)
        ->and($connection->received('app:authenticated'))->toBeTrue()
        ->and($connection->state('token.claims')->hasExpired(0))->toBeFalse();
});

it('accepts a re-authenticate with another subject once the cached claims expired', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-first'])],
    ]);
    $connection->setState('token.claims', new TokenClaims('u-first', null, null, ['exp' => time() - 3600]));
    $connection->messages = [];

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => makeToken(['sub' => 'u-second'])],
    ]);

    expect($disposition)->toBe(MessageDisposition::Handled)
        ->and($connection->received('app:authenticated'))->toBeTrue()
        ->and($connection->state('token.claims')->userId())->toBe('u-second');
});

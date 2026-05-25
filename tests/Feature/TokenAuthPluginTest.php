<?php

use Firebase\JWT\JWT;
use Webpatser\Resonate\Contracts\ApplicationProvider;
use Webpatser\Resonate\Plugins\MessageDisposition;
use Webpatser\Resonate\Plugins\PluginContext;
use Webpatser\Resonate\Protocols\Pusher\Contracts\ChannelManager;
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

function makeToken(array $claims = []): string
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
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-billing', 'token' => 'not.a.real.jwt'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and(app(ChannelManager::class)->for(app('app-fixture'))->find('private-billing'))->toBeNull();
});

it('rejects a subscribe with a token not authorized for the channel', function () {
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
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'app:authenticate',
        'data' => ['token' => 'not-a-jwt'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue()
        ->and($connection->state('token.claims'))->toBeNull();
});

it('rejects a tokenless subscribe when no pre-auth happened', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, [
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-foo'],
    ]);

    expect($disposition)->toBe(MessageDisposition::Rejected)
        ->and($connection->received('pusher:error'))->toBeTrue();
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

it('relays unrelated events untouched', function () {
    $plugin = bootPlugin();
    $connection = makeConnection();

    $disposition = $plugin->onMessage($connection, ['event' => 'pusher:ping', 'data' => []]);

    expect($disposition)->toBe(MessageDisposition::Relay);
});

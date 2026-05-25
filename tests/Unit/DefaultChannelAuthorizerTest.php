<?php

use Webpatser\ResonateTokenAuth\DefaultChannelAuthorizer;
use Webpatser\ResonateTokenAuth\TokenClaims;

it('authorizes a private channel with any valid token', function () {
    $authorizer = new DefaultChannelAuthorizer;

    expect($authorizer->authorize(new TokenClaims('u-1'), 'private-foo'))->toBeTrue();
});

it('rejects a presence channel when the token has no user id', function () {
    $authorizer = new DefaultChannelAuthorizer;

    expect($authorizer->authorize(new TokenClaims(''), 'presence-room'))->toBeFalse();
});

it('authorizes a presence channel when the token has a user id', function () {
    $authorizer = new DefaultChannelAuthorizer;

    expect($authorizer->authorize(new TokenClaims('u-7'), 'presence-room'))->toBeTrue();
});

it('matches a per-token channel glob', function () {
    $authorizer = new DefaultChannelAuthorizer;
    $claims = new TokenClaims('u-7', channels: ['presence-chat.*']);

    expect($authorizer->authorize($claims, 'presence-chat.42'))->toBeTrue()
        ->and($authorizer->authorize($claims, 'presence-other'))->toBeFalse();
});

it('rejects a channel not in the per-token allow-list', function () {
    $authorizer = new DefaultChannelAuthorizer;
    $claims = new TokenClaims('u-7', channels: ['private-billing']);

    expect($authorizer->authorize($claims, 'private-other'))->toBeFalse();
});

it('treats an empty channels claim as no limit', function () {
    $authorizer = new DefaultChannelAuthorizer;

    expect($authorizer->authorize(new TokenClaims('u-7', channels: []), 'private-anything'))->toBeTrue();
});

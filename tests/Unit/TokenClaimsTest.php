<?php

use Webpatser\ResonateTokenAuth\TokenClaims;

it('reads the expiry from the raw claim bag', function () {
    $claims = new TokenClaims('u-1', raw: ['exp' => 1_800_000_000]);

    expect($claims->expiresAt())->toBe(1_800_000_000);
});

it('reads a numeric-string expiry', function () {
    $claims = new TokenClaims('u-1', raw: ['exp' => '1800000000']);

    expect($claims->expiresAt())->toBe(1_800_000_000);
});

it('reports no expiry when the claim bag has none it can read', function () {
    expect((new TokenClaims('u-1'))->expiresAt())->toBeNull()
        ->and((new TokenClaims('u-1', raw: ['exp' => 'soon']))->expiresAt())->toBeNull();
});

it('reports claims past their expiry as expired', function () {
    $claims = new TokenClaims('u-1', raw: ['exp' => time() - 60]);

    expect($claims->hasExpired())->toBeTrue();
});

it('reports claims within their expiry as live', function () {
    $claims = new TokenClaims('u-1', raw: ['exp' => time() + 60]);

    expect($claims->hasExpired())->toBeFalse();
});

it('applies the leeway when checking expiry', function () {
    $claims = new TokenClaims('u-1', raw: ['exp' => time() - 10]);

    expect($claims->hasExpired(leeway: 30))->toBeFalse()
        ->and($claims->hasExpired(leeway: 5))->toBeTrue();
});

it('treats claims with no readable expiry as expired', function () {
    // These are cached for the life of a socket. An expiry that cannot be
    // re-checked must not be read as "never expires".
    expect((new TokenClaims('u-1'))->hasExpired())->toBeTrue();
});

it('defaults the channel allow-list to absent rather than empty', function () {
    expect((new TokenClaims('u-1'))->channels())->toBeNull();
});

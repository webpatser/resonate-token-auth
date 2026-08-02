<?php

use Firebase\JWT\JWT;
use Webpatser\ResonateTokenAuth\JwtAuthenticator;

function makeJwtAuthenticator(
    ?string $issuer = null,
    ?string $audience = null,
    array $claimMap = ['user_id' => 'sub', 'user_info' => 'user_info', 'channels' => 'channels'],
    int $leeway = 30,
): JwtAuthenticator {
    return new JwtAuthenticator(
        algorithm: 'HS256',
        key: 'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256',
        issuer: $issuer,
        audience: $audience,
        leeway: $leeway,
        claimMap: $claimMap,
    );
}

function encodeJwt(array $payload, string $secret = 'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256', string $alg = 'HS256'): string
{
    return JWT::encode($payload + ['iat' => time(), 'exp' => time() + 60], $secret, $alg);
}

it('decodes a valid HS256 token and extracts claims', function () {
    $token = encodeJwt([
        'sub' => 'u-1',
        'user_info' => ['name' => 'Alice'],
        'channels' => ['private-*'],
    ]);

    $claims = makeJwtAuthenticator()->validate($token);

    expect($claims)->not->toBeNull()
        ->and($claims->userId())->toBe('u-1')
        ->and($claims->userInfo())->toBe(['name' => 'Alice'])
        ->and($claims->channels())->toBe(['private-*']);
});

it('returns null for a token signed with the wrong secret', function () {
    $token = encodeJwt(['sub' => 'u-1'], secret: 'wrong-secret-also-padded-to-thirty-two-bytes-for-hs256');

    expect(makeJwtAuthenticator()->validate($token))->toBeNull();
});

it('returns null for an expired token', function () {
    $token = JWT::encode(['sub' => 'u-1', 'iat' => time() - 600, 'exp' => time() - 60], 'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256', 'HS256');

    expect(makeJwtAuthenticator()->validate($token))->toBeNull();
});

it('returns null when iss does not match the configured issuer', function () {
    $token = encodeJwt(['sub' => 'u-1', 'iss' => 'wrong-issuer']);

    expect(makeJwtAuthenticator(issuer: 'expected-issuer')->validate($token))->toBeNull();
});

it('returns null when aud does not match the configured audience', function () {
    $token = encodeJwt(['sub' => 'u-1', 'aud' => 'other-app']);

    expect(makeJwtAuthenticator(audience: 'resonate')->validate($token))->toBeNull();
});

it('accepts an aud claim that is a list containing the configured audience', function () {
    $token = encodeJwt(['sub' => 'u-1', 'aud' => ['web', 'resonate', 'mobile']]);

    expect(makeJwtAuthenticator(audience: 'resonate')->validate($token))->not->toBeNull();
});

it('returns null when the user id claim is missing', function () {
    $token = encodeJwt(['user_info' => ['name' => 'Alice']]);

    expect(makeJwtAuthenticator()->validate($token))->toBeNull();
});

it('honours a custom claim map', function () {
    $token = encodeJwt(['uid' => 'u-7', 'info' => ['email' => 'a@x']]);

    $claims = makeJwtAuthenticator(
        claimMap: ['user_id' => 'uid', 'user_info' => 'info', 'channels' => 'rooms'],
    )->validate($token);

    expect($claims->userId())->toBe('u-7')
        ->and($claims->userInfo())->toBe(['email' => 'a@x']);
});

it('returns null for garbage input', function () {
    expect(makeJwtAuthenticator()->validate('not.a.jwt'))->toBeNull()
        ->and(makeJwtAuthenticator()->validate(''))->toBeNull();
});

it('returns null for a token minted without an exp claim', function () {
    // php-jwt only checks exp when it is present, so a token without one used
    // to decode cleanly and stay valid forever.
    $token = JWT::encode(
        ['sub' => 'u-1', 'iat' => time()],
        'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256',
        'HS256',
    );

    expect(makeJwtAuthenticator()->validate($token))->toBeNull();
});

it('reports an absent channels claim as null, not as an empty allow-list', function () {
    $claims = makeJwtAuthenticator()->validate(encodeJwt(['sub' => 'u-1']));

    expect($claims->channels())->toBeNull();
});

it('keeps a present but empty channels claim as an empty allow-list', function () {
    // The distinction is the whole fix: null means "no claim, no limit",
    // [] means "the issuer sent an allow-list that permits nothing".
    $claims = makeJwtAuthenticator()->validate(encodeJwt(['sub' => 'u-1', 'channels' => []]));

    expect($claims->channels())->toBe([]);
});

it('rejects a channels claim that is not a list of strings', function (mixed $channels) {
    $token = encodeJwt(['sub' => 'u-1', 'channels' => $channels]);

    expect(makeJwtAuthenticator()->validate($token))->toBeNull();
})->with([
    'a bare string' => 'private-foo',
    'an integer' => 5,
    'a boolean' => true,
    'an object' => [['room' => 'private-foo']],
    'a list with a non-string entry' => [['private-foo', 5]],
    'a list with a nested list' => [['private-foo', ['private-bar']]],
]);

it('restores the global JWT leeway after a successful decode', function () {
    JWT::$leeway = 7;

    makeJwtAuthenticator(leeway: 300)->validate(encodeJwt(['sub' => 'u-1']));

    expect(JWT::$leeway)->toBe(7);

    JWT::$leeway = 0;
});

it('restores the global JWT leeway when decoding throws', function () {
    JWT::$leeway = 7;

    makeJwtAuthenticator(leeway: 300)->validate('not.a.jwt');

    expect(JWT::$leeway)->toBe(7);

    JWT::$leeway = 0;
});

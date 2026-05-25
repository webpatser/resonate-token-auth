<?php

use Firebase\JWT\JWT;
use Webpatser\ResonateTokenAuth\JwtAuthenticator;

function makeJwtAuthenticator(
    ?string $issuer = null,
    ?string $audience = null,
    array $claimMap = ['user_id' => 'sub', 'user_info' => 'user_info', 'channels' => 'channels'],
): JwtAuthenticator {
    return new JwtAuthenticator(
        algorithm: 'HS256',
        key: 'jwt-test-secret-padded-to-thirty-two-bytes-or-more-for-hs256',
        issuer: $issuer,
        audience: $audience,
        leeway: 30,
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

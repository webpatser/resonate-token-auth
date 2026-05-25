<?php

namespace Webpatser\ResonateTokenAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Throwable;
use Webpatser\ResonateTokenAuth\Contracts\TokenAuthenticator;

/**
 * Default token validator: decodes and verifies a JWT with firebase/php-jwt.
 *
 * Supports HS256/HS384/HS512 with a shared secret and RS256/RS384/RS512 plus
 * ES256/ES384 with a PEM public key. The library checks `exp`, `nbf`, and
 * `iat` automatically (with the configured leeway); this class additionally
 * enforces `iss` and `aud` when they are configured.
 */
class JwtAuthenticator implements TokenAuthenticator
{
    /**
     * @param  array<string, string>  $claimMap  Maps logical names (`user_id`, `user_info`, `channels`) to JWT claim names.
     */
    public function __construct(
        protected string $algorithm,
        protected string $key,
        protected ?string $issuer,
        protected ?string $audience,
        protected int $leeway,
        protected array $claimMap,
    ) {
        //
    }

    /**
     * Validate a JWT; return its claims on success, null on any failure.
     */
    public function validate(string $token): ?TokenClaims
    {
        // The library reads leeway from a static property, so set it for this
        // decode. The window is small and the property is process-local.
        JWT::$leeway = $this->leeway;

        try {
            $decoded = JWT::decode($token, new Key($this->key, $this->algorithm));
        } catch (Throwable) {
            return null;
        }

        try {
            $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (! is_array($claims)) {
            return null;
        }

        if ($this->issuer !== null && (string) ($claims['iss'] ?? '') !== $this->issuer) {
            return null;
        }

        if ($this->audience !== null && ! $this->audienceMatches($claims['aud'] ?? null)) {
            return null;
        }

        $userIdClaim = $this->claimMap['user_id'] ?? 'sub';
        $userId = $claims[$userIdClaim] ?? null;

        if ($userId === null || $userId === '') {
            return null;
        }

        $channels = $claims[$this->claimMap['channels'] ?? 'channels'] ?? [];

        return new TokenClaims(
            userId: (string) $userId,
            userInfo: $claims[$this->claimMap['user_info'] ?? 'user_info'] ?? null,
            channels: array_values(array_filter((array) $channels, 'is_string')),
            raw: $claims,
        );
    }

    /**
     * Determine whether the configured audience matches the token's `aud`.
     */
    protected function audienceMatches(mixed $aud): bool
    {
        if (is_string($aud)) {
            return $aud === $this->audience;
        }

        if (is_array($aud)) {
            return in_array($this->audience, $aud, true);
        }

        return false;
    }
}

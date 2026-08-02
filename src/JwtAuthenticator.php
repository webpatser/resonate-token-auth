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
 * requires `exp` to be present at all, enforces `iss` and `aud` when they are
 * configured, and rejects a malformed `channels` claim rather than coercing it.
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
        // The library reads leeway from a global static, so it is set for the
        // span of this decode and put back afterwards. Assigning it and walking
        // away leaked this package's window into every other firebase/php-jwt
        // consumer in the process (API guards, queue workers, other packages),
        // which silently widened their clock tolerance for the rest of the run.
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;

        try {
            $decoded = JWT::decode($token, new Key($this->key, $this->algorithm));
        } catch (Throwable) {
            return null;
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        try {
            $claims = json_decode(json_encode($decoded, JSON_THROW_ON_ERROR), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        }

        if (! is_array($claims)) {
            return null;
        }

        // php-jwt only validates `exp` when the claim is there, so a token
        // minted without one decoded cleanly and never went stale. Presence is
        // mandatory here; the library has already checked the value itself.
        if (! is_numeric($claims['exp'] ?? null)) {
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

        $channelsClaim = $this->claimMap['channels'] ?? 'channels';
        $channels = null;

        if (array_key_exists($channelsClaim, $claims)) {
            $declared = $claims[$channelsClaim];

            // A malformed allow-list is a rejection, not something to coerce.
            // The old `(array) $declared` plus is_string filter quietly turned a
            // scalar, an object, or a list with junk in it into an empty array,
            // and an empty array used to mean "no restriction": malformed input
            // failed open onto every private and presence channel on the server.
            if (! is_array($declared) || ! array_is_list($declared)) {
                return null;
            }

            $channels = [];

            foreach ($declared as $pattern) {
                if (! is_string($pattern)) {
                    return null;
                }

                $channels[] = $pattern;
            }
        }

        return new TokenClaims(
            userId: (string) $userId,
            userInfo: $claims[$this->claimMap['user_info'] ?? 'user_info'] ?? null,
            channels: $channels,
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

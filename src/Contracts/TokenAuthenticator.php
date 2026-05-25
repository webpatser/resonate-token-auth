<?php

namespace Webpatser\ResonateTokenAuth\Contracts;

use Webpatser\ResonateTokenAuth\JwtAuthenticator;
use Webpatser\ResonateTokenAuth\TokenClaims;

/**
 * Validates a token string and returns its claims.
 *
 * The default implementation is a JWT validator
 * ({@see JwtAuthenticator}); rebind this contract
 * in a service provider to support other token formats (Sanctum, opaque
 * lookup, an external introspection endpoint).
 */
interface TokenAuthenticator
{
    /**
     * Validate the token; return its claims on success, or null on failure.
     *
     * Implementations must not throw on bad input. Treat any validation
     * failure as a null return so the plugin can produce a uniform error.
     */
    public function validate(string $token): ?TokenClaims;
}

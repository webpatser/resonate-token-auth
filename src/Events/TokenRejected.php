<?php

namespace Webpatser\ResonateTokenAuth\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * The plugin rejected a token-based authenticate or subscribe.
 *
 * Dispatched once per rejection. The `$reason` is a stable, low-cardinality
 * label so a metrics consumer can bucket: `'missing_token'`, `'invalid_token'`,
 * `'unauthorized_channel'`, `'expired_token'`, or `'application_mismatch'`.
 */
class TokenRejected
{
    use Dispatchable;

    public const MISSING_TOKEN = 'missing_token';

    public const INVALID_TOKEN = 'invalid_token';

    public const UNAUTHORIZED_CHANNEL = 'unauthorized_channel';

    /**
     * Cached pre-authentication claims outlived their `exp`.
     *
     * Distinct from `invalid_token`: nothing is wrong with the client, its
     * pre-auth simply went stale and it needs to send a fresh token.
     */
    public const EXPIRED_TOKEN = 'expired_token';

    /**
     * The token is valid but was minted for a different application.
     *
     * On a multi-application server this is the signal that one tenant's token
     * is being presented on another tenant's app key.
     */
    public const APPLICATION_MISMATCH = 'application_mismatch';

    /**
     * Create a new event instance.
     */
    public function __construct(public string $reason)
    {
        //
    }
}

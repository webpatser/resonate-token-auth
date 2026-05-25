<?php

namespace Webpatser\ResonateTokenAuth\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * The plugin rejected a token-based authenticate or subscribe.
 *
 * Dispatched once per rejection. The `$reason` is a stable, low-cardinality
 * label so a metrics consumer can bucket: `'missing_token'`, `'invalid_token'`,
 * or `'unauthorized_channel'`.
 */
class TokenRejected
{
    use Dispatchable;

    public const MISSING_TOKEN = 'missing_token';

    public const INVALID_TOKEN = 'invalid_token';

    public const UNAUTHORIZED_CHANNEL = 'unauthorized_channel';

    /**
     * Create a new event instance.
     */
    public function __construct(public string $reason)
    {
        //
    }
}

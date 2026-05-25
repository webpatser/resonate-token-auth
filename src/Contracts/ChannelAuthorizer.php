<?php

namespace Webpatser\ResonateTokenAuth\Contracts;

use Webpatser\ResonateTokenAuth\DefaultChannelAuthorizer;
use Webpatser\ResonateTokenAuth\TokenClaims;

/**
 * Decides whether a validated token may subscribe to a channel.
 *
 * The default implementation
 * ({@see DefaultChannelAuthorizer}) trusts any
 * valid token for private channels, requires a `user_id` for presence
 * channels, and honours a per-token `channels` claim when present. Rebind
 * this contract to enforce tenant rules, role checks, or external lookups.
 */
interface ChannelAuthorizer
{
    /**
     * Determine whether the claims permit a subscribe to the channel.
     */
    public function authorize(TokenClaims $claims, string $channel): bool;
}

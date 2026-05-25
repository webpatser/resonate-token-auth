<?php

namespace Webpatser\ResonateTokenAuth;

use Webpatser\ResonateTokenAuth\Contracts\ChannelAuthorizer;

/**
 * The default {@see ChannelAuthorizer}.
 *
 * The rules are deliberately small:
 *
 * - Presence channels require a `user_id` on the token. (The plugin needs
 *   one anyway to synthesize the presence `channel_data`.)
 * - When the token carries a `channels` claim, the channel must match at
 *   least one entry; glob patterns (`fnmatch`) are honoured, so
 *   `presence-chat.*` matches `presence-chat.42`.
 * - When the token has no `channels` claim, any private or presence channel
 *   is allowed: the token's validity is the trust boundary.
 *
 * Rebind this contract in a service provider for finer rules (tenancy,
 * role checks, external lookups).
 */
class DefaultChannelAuthorizer implements ChannelAuthorizer
{
    /**
     * Decide whether the claims permit a subscribe to the channel.
     */
    public function authorize(TokenClaims $claims, string $channel): bool
    {
        if (str_starts_with($channel, 'presence-') && $claims->userId() === '') {
            return false;
        }

        $allowed = $claims->channels();

        if ($allowed === []) {
            return true;
        }

        foreach ($allowed as $pattern) {
            if (fnmatch($pattern, $channel)) {
                return true;
            }
        }

        return false;
    }
}

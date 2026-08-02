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
 *   `presence-chat.*` matches `presence-chat.42`. A claim that is present but
 *   empty matches nothing and therefore allows nothing.
 * - Only when the token has no `channels` claim at all is any private or
 *   presence channel allowed: the token's validity is the trust boundary.
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

        // Null is "the token carried no allow-list", the only case that means
        // no token-level restriction. An empty list is an allow-list that
        // happens to permit nothing: reading it as "no restriction" made a
        // token whose claim was emptied (or malformed enough to collapse to
        // nothing) a pass to every private and presence channel on the server.
        if ($allowed === null) {
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

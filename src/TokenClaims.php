<?php

namespace Webpatser\ResonateTokenAuth;

/**
 * The validated claims pulled from a token, in a shape the plugin can use.
 *
 * Authenticators return this; authorizers consume it; the plugin reads
 * `userId()` and `userInfo()` when synthesizing presence channel_data, and
 * `channels()` when an authorizer wants to enforce a per-token allow-list.
 * The raw claim bag is preserved so a custom authorizer can read anything
 * the issuer attached.
 */
final class TokenClaims
{
    /**
     * @param  array<string, mixed>  $raw  The decoded JWT payload (or equivalent).
     * @param  mixed  $userInfo  Optional presence user info; any JSON-able value.
     * @param  list<string>  $channels  Optional per-token channel allow-list.
     */
    public function __construct(
        public readonly string $userId,
        public readonly mixed $userInfo = null,
        public readonly array $channels = [],
        public readonly array $raw = [],
    ) {
        //
    }

    /**
     * The presence user id, as a string (Pusher's wire format).
     */
    public function userId(): string
    {
        return $this->userId;
    }

    /**
     * The presence user info, or null when the token did not carry any.
     */
    public function userInfo(): mixed
    {
        return $this->userInfo;
    }

    /**
     * The per-token channel allow-list. Empty means "no token-level limit"
     * (the authorizer's own rules still apply).
     *
     * @return list<string>
     */
    public function channels(): array
    {
        return $this->channels;
    }

    /**
     * The raw claim bag, for authorizers that need to read custom claims.
     *
     * @return array<string, mixed>
     */
    public function raw(): array
    {
        return $this->raw;
    }

    /**
     * Read one raw claim by name.
     */
    public function claim(string $name, mixed $default = null): mixed
    {
        return $this->raw[$name] ?? $default;
    }
}

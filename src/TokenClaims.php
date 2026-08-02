<?php

namespace Webpatser\ResonateTokenAuth;

/**
 * The validated claims pulled from a token, in a shape the plugin can use.
 *
 * Authenticators return this; authorizers consume it; the plugin reads
 * `userId()` and `userInfo()` when synthesizing presence channel_data, and
 * `channels()` when an authorizer wants to enforce a per-token allow-list.
 * The raw claim bag is preserved so a custom authorizer can read anything
 * the issuer attached, and so the plugin can re-check `exp` on claims it
 * cached for a pre-authenticated connection.
 */
final class TokenClaims
{
    /**
     * @param  array<string, mixed>  $raw  The decoded JWT payload (or equivalent).
     * @param  mixed  $userInfo  Optional presence user info; any JSON-able value.
     * @param  list<string>|null  $channels  The per-token channel allow-list, or
     *                                       null when the token carried no
     *                                       channels claim at all. An empty list
     *                                       is a real allow-list that permits
     *                                       nothing, not "no restriction".
     */
    public function __construct(
        public readonly string $userId,
        public readonly mixed $userInfo = null,
        public readonly ?array $channels = null,
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
     * The per-token channel allow-list.
     *
     * Null means the token carried no channels claim, so there is no
     * token-level limit and the authorizer's own rules decide. A list is the
     * allow-list itself, and an empty one allows nothing: a claim the issuer
     * did send has to be honoured as sent, otherwise emptied or malformed
     * input widens access instead of narrowing it.
     *
     * @return list<string>|null
     */
    public function channels(): ?array
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

    /**
     * The token's expiry as a Unix timestamp, or null when it carries none
     * that can be read as one.
     */
    public function expiresAt(): ?int
    {
        $expiry = $this->raw['exp'] ?? null;

        return is_numeric($expiry) ? (int) $expiry : null;
    }

    /**
     * Determine whether these claims have expired.
     *
     * Claims with no readable `exp` are reported as expired. A pre-authenticated
     * connection caches its claims for the whole life of the socket, and an
     * expiry that cannot be re-checked cannot be trusted for that long: a claim
     * bag carrying no expiry would authorize subscribes forever, which is the
     * same hole the mandatory `exp` closes on the validation side.
     */
    public function hasExpired(int $leeway = 0, ?int $now = null): bool
    {
        $expiresAt = $this->expiresAt();

        if ($expiresAt === null) {
            return true;
        }

        return ($now ?? time()) > $expiresAt + $leeway;
    }
}

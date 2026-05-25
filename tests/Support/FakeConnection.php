<?php

namespace Webpatser\ResonateTokenAuth\Tests\Support;

use Webpatser\Resonate\Application;
use Webpatser\Resonate\Contracts\Connection;

/**
 * A minimal in-memory Connection for driving the plugin in tests.
 *
 * Records every message sent so tests can assert that the right Pusher
 * frames were emitted (pusher:error, app:authenticated,
 * pusher_internal:subscription_succeeded).
 */
class FakeConnection extends Connection
{
    /**
     * Every message the server sent through this connection.
     *
     * @var list<string>
     */
    public array $messages = [];

    /**
     * Whether the server asked to close this connection.
     */
    public bool $terminated = false;

    /**
     * Create a new fake connection.
     */
    public function __construct(protected string $socketId, protected Application $appInstance)
    {
        $this->origin = 'http://localhost';
    }

    /**
     * Get the raw socket connection identifier.
     */
    public function identifier(): string
    {
        return $this->socketId;
    }

    /**
     * Get the normalized socket ID.
     */
    public function id(): string
    {
        return $this->socketId;
    }

    /**
     * Get the application the connection belongs to.
     */
    public function app(): Application
    {
        return $this->appInstance;
    }

    /**
     * Send a message to the connection.
     */
    public function send(string $message): void
    {
        $this->messages[] = $message;
    }

    /**
     * Send a control frame to the connection.
     */
    public function control(string $type = self::CONTROL_PING): void
    {
        //
    }

    /**
     * Terminate the connection.
     */
    public function terminate(): void
    {
        $this->terminated = true;
    }

    /**
     * Determine whether the connection received an event with the given name.
     */
    public function received(string $event): bool
    {
        foreach ($this->messages as $message) {
            $decoded = json_decode($message, associative: true);

            if (is_array($decoded) && ($decoded['event'] ?? null) === $event) {
                return true;
            }
        }

        return false;
    }
}

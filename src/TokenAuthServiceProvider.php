<?php

namespace Webpatser\ResonateTokenAuth;

use Illuminate\Support\ServiceProvider;
use Webpatser\ResonateTokenAuth\Contracts\ChannelAuthorizer;
use Webpatser\ResonateTokenAuth\Contracts\TokenAuthenticator;

/**
 * Wires the token-auth plugin into a host Laravel application.
 *
 * Binds the two pluggable contracts to their defaults. Consumers swap either
 * by rebinding the contract in their own service provider.
 *
 * The {@see TokenAuthPlugin} itself is not bound here: Resonate instantiates
 * it from the `plugins` array in `config/reverb.php`.
 */
class TokenAuthServiceProvider extends ServiceProvider
{
    /**
     * Register the package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/resonate-token-auth.php', 'resonate-token-auth');

        $this->app->bind(TokenAuthenticator::class, function ($app) {
            $config = $app['config']->get('resonate-token-auth', []);

            $algorithm = (string) ($config['algorithm'] ?? 'HS256');
            $key = str_starts_with($algorithm, 'HS')
                ? (string) ($config['secret'] ?? '')
                : (string) ($config['public_key'] ?? '');

            return new JwtAuthenticator(
                algorithm: $algorithm,
                key: $key,
                issuer: $config['issuer'] ?? null,
                audience: $config['audience'] ?? null,
                leeway: (int) ($config['leeway'] ?? 30),
                claimMap: (array) ($config['claims'] ?? []),
            );
        });

        $this->app->bind(ChannelAuthorizer::class, DefaultChannelAuthorizer::class);
    }

    /**
     * Bootstrap the package services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/resonate-token-auth.php' => $this->app->configPath('resonate-token-auth.php'),
            ], 'resonate-token-auth-config');
        }
    }
}

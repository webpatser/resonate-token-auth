<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Signing algorithm
    |--------------------------------------------------------------------------
    |
    | The JWT signing algorithm the default validator expects. Use a symmetric
    | algorithm (HS256, HS384, HS512) when your Laravel app issues tokens with
    | a shared secret. Use an asymmetric one (RS256, RS384, RS512, ES256,
    | ES384) when tokens are issued elsewhere and verified against a public
    | key.
    |
    */

    'algorithm' => env('RESONATE_TOKEN_AUTH_ALG', 'HS256'),

    /*
    |--------------------------------------------------------------------------
    | Keys
    |--------------------------------------------------------------------------
    |
    | `secret` is used for HS* algorithms; `public_key` (PEM) is used for RS*
    | and ES* algorithms. Whichever matches the configured algorithm is read,
    | the other is ignored.
    |
    */

    'secret' => env('RESONATE_TOKEN_AUTH_SECRET'),

    'public_key' => env('RESONATE_TOKEN_AUTH_PUBLIC_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Issuer and audience
    |--------------------------------------------------------------------------
    |
    | Optional. When set, the default validator rejects a token whose `iss`
    | or `aud` claim does not match.
    |
    */

    'issuer' => env('RESONATE_TOKEN_AUTH_ISSUER'),

    'audience' => env('RESONATE_TOKEN_AUTH_AUDIENCE'),

    /*
    |--------------------------------------------------------------------------
    | Clock leeway (seconds)
    |--------------------------------------------------------------------------
    |
    | A small window applied to `exp`, `nbf`, and `iat` so a tiny clock skew
    | between issuer and verifier does not reject otherwise-valid tokens.
    |
    */

    'leeway' => (int) env('RESONATE_TOKEN_AUTH_LEEWAY', 30),

    /*
    |--------------------------------------------------------------------------
    | Application binding
    |--------------------------------------------------------------------------
    |
    | Resonate can serve several applications from one process, each with its
    | own key and secret, while the JWT settings above are global. A token must
    | therefore say which application it was minted for, and the plugin rejects
    | it on any other one; otherwise one tenant's token is accepted on every
    | tenant's app key.
    |
    | A token whose binding claim names a different application is always
    | rejected. This switch only decides what happens to a token that carries
    | no binding claim at all: true (the default) rejects it, false accepts it.
    | Set it to false only while migrating issuers that do not mint the claim
    | yet, and put it back to true once they do.
    |
    */

    'require_app_claim' => (bool) env('RESONATE_TOKEN_AUTH_REQUIRE_APP_CLAIM', true),

    /*
    |--------------------------------------------------------------------------
    | Pin identity
    |--------------------------------------------------------------------------
    |
    | Per-subscribe tokens are independent bearer tokens, so a connection that
    | pre-authenticated as one user can still subscribe with a token minted for
    | another. Set this to true to reject a per-subscribe token whose subject
    | (the user id claim) differs from the identity the connection
    | pre-authenticated as. Connections that never sent `app:authenticate` are
    | not affected. Off by default.
    |
    */

    'pin_identity' => (bool) env('RESONATE_TOKEN_AUTH_PIN_IDENTITY', false),

    /*
    |--------------------------------------------------------------------------
    | Claim mapping
    |--------------------------------------------------------------------------
    |
    | Which JWT claims the validator reads for the user id, the optional
    | presence user info, the optional per-token channel allow-list, and the
    | application the token is bound to.
    |
    */

    'claims' => [
        'user_id' => env('RESONATE_TOKEN_AUTH_USER_ID_CLAIM', 'sub'),
        'user_info' => env('RESONATE_TOKEN_AUTH_USER_INFO_CLAIM', 'user_info'),
        'channels' => env('RESONATE_TOKEN_AUTH_CHANNELS_CLAIM', 'channels'),
        'app_id' => env('RESONATE_TOKEN_AUTH_APP_ID_CLAIM', 'app_id'),
    ],

];

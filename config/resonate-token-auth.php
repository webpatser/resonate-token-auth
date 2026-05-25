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
    | Claim mapping
    |--------------------------------------------------------------------------
    |
    | Which JWT claims the validator reads for the user id, the optional
    | presence user info, and the optional per-token channel allow-list.
    |
    */

    'claims' => [
        'user_id' => env('RESONATE_TOKEN_AUTH_USER_ID_CLAIM', 'sub'),
        'user_info' => env('RESONATE_TOKEN_AUTH_USER_INFO_CLAIM', 'user_info'),
        'channels' => env('RESONATE_TOKEN_AUTH_CHANNELS_CLAIM', 'channels'),
    ],

];

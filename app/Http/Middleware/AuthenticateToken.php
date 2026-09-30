<?php

namespace App\Http\Middleware;

use App\Support\AuthTokens;
use App\User;
use Closure;

class AuthenticateToken
{
    /**
     * Require a valid Bearer token and expose the user to the controller.
     *
     * A token issued to a user who already has Google Authenticator is
     * "unverified" until the 6-digit code is entered. Unverified tokens may
     * only reach login/verify and logout.
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $payload = AuthTokens::payload($request);

        if (!$payload) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        $user = User::find($payload['user_id']);

        if (!$user) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        if (empty($payload['verified']) && !self::allowedUnverified($request)) {
            return response()->json([
                'message' => 'Authenticator code required',
                'code' => 'totp_required',
            ], 403);
        }

        $request->setUserResolver(function () use ($user) {
            return $user;
        });

        return $next($request);
    }

    private static function allowedUnverified($request)
    {
        if (strtoupper($request->method()) !== 'POST') {
            return false;
        }

        return $request->is('api/login/verify')
            || $request->is('api/logout');
    }
}

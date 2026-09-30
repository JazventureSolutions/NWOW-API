<?php

namespace App\Support;

use App\User;
use Illuminate\Support\Facades\Cache;

/**
 * Stateless bearer tokens kept in the cache.
 * No Passport/JWT dependency, so only app/ files need re-uploading.
 */
class AuthTokens
{
    const TTL_MINUTES = 10080; // 7 days

    /**
     * Issue a token for the user and invalidate any previous one.
     *
     * $verified = false leaves the session in a "password accepted, but the
     * authenticator code has not been entered yet" state. Only a couple of
     * routes accept an unverified token.
     */
    public static function issue(User $user, $verified = true)
    {
        self::revokeFor($user->username);

        $token = bin2hex(random_bytes(32));

        Cache::put(self::tokenKey($token), [
            'user_id' => (int) $user->id,
            'verified' => (bool) $verified,
        ], self::TTL_MINUTES * 60);
        Cache::put(self::activeKey($user->username), $token, self::TTL_MINUTES * 60);

        return $token;
    }

    /**
     * Raw session payload for this request, or null.
     */
    public static function payload($request)
    {
        $token = self::tokenFromRequest($request);
        if ($token === null) {
            return null;
        }

        $payload = Cache::get(self::tokenKey($token));
        if (!is_array($payload) || empty($payload['user_id'])) {
            return null;
        }

        return $payload;
    }

    /**
     * Resolve the authenticated user for this request, or null.
     */
    public static function user($request)
    {
        $payload = self::payload($request);

        return $payload ? User::find($payload['user_id']) : null;
    }

    /**
     * Has the authenticator code been entered for this session?
     */
    public static function isVerified($request)
    {
        $payload = self::payload($request);

        return $payload && !empty($payload['verified']);
    }

    /**
     * Promote the current session to fully verified.
     */
    public static function markVerified($request)
    {
        $token = self::tokenFromRequest($request);
        if ($token === null) {
            return false;
        }

        $key = self::tokenKey($token);
        $payload = Cache::get($key);
        if (!is_array($payload)) {
            return false;
        }

        $payload['verified'] = true;
        Cache::put($key, $payload, self::TTL_MINUTES * 60);

        return true;
    }

    /**
     * Forget the token used by this request.
     */
    public static function revoke($request)
    {
        $token = self::tokenFromRequest($request);
        if ($token === null) {
            return;
        }

        $payload = Cache::get(self::tokenKey($token));
        Cache::forget(self::tokenKey($token));

        if (is_array($payload) && !empty($payload['user_id'])) {
            $user = User::find($payload['user_id']);
            if ($user) {
                self::revokeFor($user->username);
            }
        }
    }

    /**
     * Kill every live session for a username (used after a password reset).
     */
    public static function revokeFor($username)
    {
        $active = Cache::pull(self::activeKey($username));
        if ($active) {
            Cache::forget(self::tokenKey($active));
        }
    }

    private static function tokenFromRequest($request)
    {
        $header = $request->header('Authorization', '');
        if (preg_match('/^Bearer\s+(.+)$/i', trim($header), $m)) {
            return trim($m[1]);
        }

        return null;
    }

    private static function tokenKey($token)
    {
        return 'auth:token:' . $token;
    }

    private static function activeKey($username)
    {
        return 'auth:active:' . strtolower($username);
    }
}

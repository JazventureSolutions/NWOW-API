<?php

namespace App\Http\Controllers;

use App\Services\TotpService;
use App\Support\AuthTokens;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;

class TotpController extends Controller
{
    const ISSUER = 'NWOW';

    const MAX_ATTEMPTS = 5;
    const LOCK_MINUTES = 15;
    const RESET_TOKEN_TTL = 300;

    /** @var TotpService */
    private $totp;

    public function __construct()
    {
        $this->totp = new TotpService();
    }

    /**
     * POST /api/totp/setup
     * Creates a fresh pending secret for the given username.
     */
    public function setup(Request $request)
    {
        $user = $request->user();

        if ($this->isLocked($user->username)) {
            return response()->json(['message' => $this->lockedMessage()], 429);
        }

        $secret = $this->totp->generateSecret();

        $user->totp_secret = $secret;
        $user->totp_confirmed_at = null;
        $user->totp_last_code = null;
        $user->totp_attempts = 0;
        $user->save();

        return response()->json([
            'username' => $user->username,
            'account' => $user->username,
            'issuer' => self::ISSUER,
            'secret' => $secret,
            'otpauth_url' => $this->totp->getOtpauthUrl($secret, $user->username, self::ISSUER),
            'digits' => 6,
            'period' => 30,
            'enabled' => false,
        ]);
    }

    /**
     * POST /api/totp/confirm
     * Activates enrolment once the user proves they scanned the key.
     */
    public function confirm(Request $request)
    {
        $data = $request->validate([
            'code' => 'required|string|max:10',
        ]);

        $user = $request->user();
        if (!$user->totp_secret) {
            return response()->json(['message' => 'Run setup first'], 400);
        }

        if ($this->isLocked($user->username)) {
            return response()->json(['message' => $this->lockedMessage()], 429);
        }

        if (!$this->totp->verify($user->totp_secret, $data['code'])) {
            $this->registerFailure($user);

            return response()->json(['message' => 'Invalid code'], 422);
        }

        $user->totp_confirmed_at = now();
        $user->totp_attempts = 0;
        $user->totp_locked_until = null;
        $user->save();

        $codes = $this->totp->generateBackupCodes();

        $user->backupCodes()->delete();
        foreach ($codes as $code) {
            $user->backupCodes()->create(['code_hash' => TotpService::hashBackupCode($code)]);
        }

        return response()->json([
            'enabled' => true,
            'backup_codes' => $codes,
            'message' => 'Authenticator activated. Store these backup codes somewhere safe.',
        ]);
    }

    /**
     * POST /api/totp/status
     */
    public function status(Request $request)
    {
        $user = $request->user();

        return response()->json([
            'enabled' => (bool) ($user && $user->totp_confirmed_at),
            'setup_started' => (bool) ($user && $user->totp_secret && !$user->totp_confirmed_at),
        ]);
    }

    /**
     * POST /api/login/verify
     * Second half of login: password was accepted, now prove possession of
     * the authenticator before the app is allowed to show anything.
     */
    public function verifyLogin(Request $request)
    {
        $data = $request->validate([
            'code' => 'required|string|max:10',
        ]);

        $user = $request->user();

        if (!$user->hasTotp()) {
            AuthTokens::markVerified($request);

            return response()->json(['success' => true, 'verified' => true]);
        }

        if ($this->isLocked($user->username)) {
            return response()->json(['message' => $this->lockedMessage()], 429);
        }

        if (!$this->codeIsValid($user, $data['code'])) {
            $this->registerFailure($user);

            return response()->json(['message' => 'Invalid code'], 422);
        }

        $this->clearFailures($user);
        AuthTokens::markVerified($request);

        return response()->json(['success' => true, 'verified' => true]);
    }

    /**
     * POST /api/totp/disable
     * Self-service removal: prove the code, then unbind the account.
     */
    public function disable(Request $request)
    {
        $data = $request->validate([
            'code' => 'required|string|max:10',
        ]);

        $user = $request->user();

        if (!$user->hasTotp()) {
            return response()->json(['message' => 'Authenticator is not set up for this account'], 400);
        }

        if ($this->isLocked($user->username)) {
            return response()->json(['message' => $this->lockedMessage()], 429);
        }

        if (!$this->codeIsValid($user, $data['code'])) {
            $this->registerFailure($user);

            return response()->json(['message' => 'Invalid code'], 422);
        }

        $this->clearFailures($user);
        $user->clearTotp();

        return response()->json([
            'success' => true,
            'message' => 'Authenticator removed. You will set it up again at your next login.',
        ]);
    }

    /**
     * POST /api/totp/verify
     * Step 1 of a password change: check the code, then hand out a
     * short-lived single-use reset token (this is the "expiring link").
     */
    public function verify(Request $request)
    {
        $data = $request->validate([
            'username' => 'required|string|max:100',
            'code' => 'required|string|max:10',
        ]);

        $user = $this->findUser($data['username']);
        if (!$user || !$user->totp_secret || !$user->totp_confirmed_at) {
            return response()->json(['message' => 'Authenticator is not set up for this account'], 400);
        }

        if ($this->isLocked($user->username)) {
            return response()->json(['message' => $this->lockedMessage()], 429);
        }

        if (!$this->codeIsValid($user, $data['code'])) {
            $this->registerFailure($user);

            return response()->json(['message' => 'Invalid code'], 422);
        }

        $this->clearFailures($user);

        $token = bin2hex(random_bytes(32));
        Cache::put(
            $this->resetKey($user->username),
            hash('sha256', $token),
            self::RESET_TOKEN_TTL
        );

        return response()->json([
            'reset_token' => $token,
            'expires_in' => self::RESET_TOKEN_TTL,
            'message' => 'Code accepted. Set your new password within 5 minutes.',
        ]);
    }

    /**
     * POST /api/password/reset
     * Step 2: burn the token and store the new password hash.
     */
    public function reset(Request $request)
    {
        $data = $request->validate([
            'username' => 'required|string|max:100',
            'reset_token' => 'required|string|max:128',
            'new_password' => 'required|string|min:6|max:255',
        ]);

        $user = $this->findUser($data['username']);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $key = $this->resetKey($user->username);
        $stored = Cache::get($key);

        if (!$stored || !hash_equals($stored, hash('sha256', $data['reset_token']))) {
            return response()->json([
                'message' => 'Reset code has expired. Request a new one.',
            ], 410);
        }

        Cache::forget($key);

        $user->password = Hash::make($data['new_password']);
        $user->save();

        // Any device still holding a session for this account must log in again.
        AuthTokens::revokeFor($user->username);

        return response()->json([
            'success' => true,
            'message' => 'Password updated.',
        ]);
    }

    /**
     * Accepts a normal 6-digit TOTP or a one-time backup code.
     */
    private function codeIsValid(User $user, $code)
    {
        $trimmed = preg_replace('/\s+/', '', (string) $code);

        if (preg_match('/^\d{6}$/', $trimmed) && $this->totp->verify($user->totp_secret, $trimmed)) {
            // Reject a replay of the code that is still on screen.
            if ($user->totp_last_code === $trimmed && $user->totp_last_used_at
                && now()->diffInSeconds($user->totp_last_used_at) < 30) {
                return false;
            }

            $user->totp_last_code = $trimmed;
            $user->totp_last_used_at = now();
            $user->save();

            return true;
        }

        return $this->consumeBackupCode($user, $trimmed);
    }

    private function consumeBackupCode(User $user, $code)
    {
        if (!preg_match('/^[A-F0-9]{4}-?[A-F0-9]{4}$/i', $code)) {
            return false;
        }

        $row = $user->backupCodes()
            ->where('code_hash', TotpService::hashBackupCode($code))
            ->whereNull('used_at')
            ->first();

        if (!$row) {
            return false;
        }

        $row->used_at = now();
        $row->save();

        return true;
    }

    private function findUser($username)
    {
        return User::where('username', $username)
            ->orWhere('email', $username)
            ->first();
    }

    private function registerFailure(User $user)
    {
        $user->totp_attempts = (int) $user->totp_attempts + 1;
        $user->save();

        if ($user->totp_attempts >= self::MAX_ATTEMPTS) {
            $user->totp_locked_until = now()->addMinutes(self::LOCK_MINUTES);
            $user->save();

            Cache::put($this->lockKey($user->username), 1, self::LOCK_MINUTES * 60);
        }
    }

    private function clearFailures(User $user)
    {
        Cache::forget($this->failKey($user->username));
        Cache::forget($this->lockKey($user->username));

        $user->totp_attempts = 0;
        $user->totp_locked_until = null;
        $user->save();
    }

    private function isLocked($username)
    {
        $user = User::where('username', $username)->first();

        if ($user && $user->totp_locked_until && now()->lessThan($user->totp_locked_until)) {
            return true;
        }

        return Cache::has($this->lockKey($username));
    }

    private function lockedMessage()
    {
        return 'Too many attempts. Try again in ' . self::LOCK_MINUTES . ' minutes.';
    }

    private function resetKey($username)
    {
        return 'totp_reset:' . $username;
    }

    private function failKey($username)
    {
        return 'totp_fail:' . $username;
    }

    private function lockKey($username)
    {
        return 'totp_lock:' . $username;
    }
}

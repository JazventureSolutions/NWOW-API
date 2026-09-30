<?php

namespace App\Http\Controllers;

use App\Support\AuthTokens;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * POST /api/login
     * Server-side authentication so accounts work on any device.
     */
    public function login(Request $request)
    {
        $data = $request->validate([
            'username' => 'required|string|max:100',
            'password' => 'required|string|max:255',
        ]);

        $user = User::where('username', $data['username'])
            ->orWhere('email', $data['username'])
            ->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response()->json(['message' => 'Incorrect username or password'], 401);
        }

        // A user who already enrolled gets an unverified session: the app must
        // collect the 6-digit code before it may show anything behind it.
        $hasTotp = $user->hasTotp();

        return response()->json([
            'token' => AuthTokens::issue($user, !$hasTotp),
            'username' => $user->username,
            'name' => $user->name,
            'role' => $user->role ?: 'user',
            'must_enrol' => !$hasTotp,
            'totp_required' => (bool) $hasTotp,
        ]);
    }

    /**
     * POST /api/logout
     */
    public function logout(Request $request)
    {
        AuthTokens::revoke($request);

        return response()->json(['success' => true]);
    }

    /**
     * GET /api/me
     */
    public function me(Request $request)
    {
        $user = $request->user();

        return response()->json([
            'username' => $user->username,
            'name' => $user->name,
            'role' => $user->role ?: 'user',
            'must_enrol' => !$user->hasTotp(),
            'totp_required' => (bool) $user->hasTotp() && !AuthTokens::isVerified($request),
        ]);
    }

    /**
     * POST /api/password/change
     * Change your own password while logged in.
     */
    public function change(Request $request)
    {
        $data = $request->validate([
            'current_password' => 'required|string|max:255',
            'new_password' => 'required|string|min:6|max:255',
        ]);

        $user = $request->user();

        if (!Hash::check($data['current_password'], $user->password)) {
            return response()->json(['message' => 'Current password is incorrect'], 422);
        }

        if (Hash::check($data['new_password'], $user->password)) {
            return response()->json(['message' => 'New password must differ from the current one'], 422);
        }

        $user->password = Hash::make($data['new_password']);
        $user->save();

        AuthTokens::revoke($request);

        return response()->json([
            'success' => true,
            'message' => 'Password updated. Please login again.',
        ]);
    }
}

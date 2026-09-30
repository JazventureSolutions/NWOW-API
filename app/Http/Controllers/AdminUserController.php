<?php

namespace App\Http\Controllers;

use App\Support\AuthTokens;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class AdminUserController extends Controller
{
    /**
     * GET /api/admin/users
     */
    public function index(Request $request)
    {
        $users = User::orderBy('username')
            ->get(['id', 'username', 'name', 'email', 'role', 'totp_secret', 'totp_confirmed_at', 'created_at'])
            ->map(function (User $user) {
                return [
                    'id' => $user->id,
                    'username' => $user->username,
                    'name' => $user->name,
                    'role' => $user->role ?: 'user',
                    'has_authenticator' => $user->hasTotp(),
                ];
            });

        return response()->json(['data' => $users->values()]);
    }

    /**
     * POST /api/admin/users
     * Super admin creates a new login for the application.
     */
    public function store(Request $request)
    {
        $data = $request->validate([
            'username' => 'required|string|min:3|max:50|regex:/^[A-Za-z0-9._-]+$/|unique:users,username',
            'name' => 'required|string|max:100',
            'password' => 'required|string|min:6|max:255',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'username' => $data['username'],
            'email' => strtolower($data['username']) . '@nwow.local',
            'password' => Hash::make($data['password']),
            'role' => 'user',
        ]);

        Log::info('admin.user_created', [
            'by' => $request->user()->username,
            'username' => $user->username,
        ]);

        return response()->json([
            'success' => true,
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'name' => $user->name,
                'role' => 'user',
                'has_authenticator' => false,
            ],
        ], 201);
    }

    /**
     * PUT /api/admin/users/{id}
     * Super admin edits any account: name, username, optional new password, optional role.
     */
    public function update(Request $request, $id)
    {
        $user = User::find($id);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $data = $request->validate([
            'username' => 'required|string|min:3|max:50|regex:/^[A-Za-z0-9._-]+$/|unique:users,username,' . $user->id,
            'name' => 'required|string|max:100',
            'password' => 'nullable|string|min:6|max:255',
            'role' => 'nullable|in:admin,user',
        ]);

        $admin = $request->user();

        if (isset($data['role']) && $data['role'] !== ($user->role ?: 'user')) {
            if ($admin->id === $user->id) {
                return response()->json(['message' => 'You cannot change your own role'], 422);
            }

            if (($user->role ?: 'user') === 'admin' && $data['role'] === 'user'
                && User::where('role', 'admin')->count() <= 1) {
                return response()->json(['message' => 'Cannot demote the last admin'], 422);
            }
        }

        $oldUsername = $user->username;
        $oldRole = $user->role ?: 'user';
        $passwordChanged = !empty($data['password']);

        $user->name = $data['name'];
        $user->username = $data['username'];

        if ($passwordChanged) {
            $user->password = Hash::make($data['password']);
        }

        if (isset($data['role'])) {
            $user->role = $data['role'];
        }

        $user->save();

        // Only a credential change invalidates the sessions opened with the old one.
        if ($oldUsername !== $user->username || $passwordChanged || $oldRole !== ($user->role ?: 'user')) {
            AuthTokens::revokeFor($oldUsername);
            if ($oldUsername !== $user->username) {
                AuthTokens::revokeFor($user->username);
            }
        }

        Log::info('admin.user_updated', [
            'by' => $admin->username,
            'user' => $user->username,
        ]);

        return response()->json([
            'success' => true,
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'name' => $user->name,
                'role' => $user->role ?: 'user',
                'has_authenticator' => $user->hasTotp(),
            ],
        ]);
    }

    /**
     * DELETE /api/admin/users/{id}
     * Super admin removes an account (not their own, never the last admin).
     */
    public function destroy(Request $request, $id)
    {
        $admin = $request->user();

        if ((int) $admin->id === (int) $id) {
            return response()->json(['message' => 'You cannot delete your own account'], 422);
        }

        $user = User::find($id);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if (($user->role ?: 'user') === 'admin' && User::where('role', 'admin')->count() <= 1) {
            return response()->json(['message' => 'Cannot delete the last admin'], 422);
        }

        AuthTokens::revokeFor($user->username);
        $user->backupCodes()->delete();
        $user->delete();

        Log::info('admin.user_deleted', [
            'by' => $admin->username,
            'user' => $user->username,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'User ' . $user->username . ' deleted',
        ]);
    }

    /**
     * POST /api/admin/users/{id}/reset-password
     * Super admin can reset any user's password.
     */
    public function resetPassword(Request $request, $id)
    {
        $data = $request->validate([
            'new_password' => 'required|string|min:6|max:255',
        ]);

        $user = User::find($id);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $user->password = Hash::make($data['new_password']);
        $user->save();

        // Force every device holding a session for this account to log in again.
        AuthTokens::revokeFor($user->username);

        Log::info('admin.password_reset', [
            'by' => $request->user()->username,
            'username' => $user->username,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Password reset for ' . $user->username,
        ]);
    }

    /**
     * POST /api/admin/users/{id}/clear-authenticator
     * Super admin unbinds a lost/broken phone from an account. No code is
     * required here - the admin is already authenticated as the owner.
     */
    public function clearAuthenticator(Request $request, $id)
    {
        $user = User::find($id);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if (!$user->hasTotp()) {
            return response()->json([
                'message' => 'Authenticator is not set up for this account',
            ], 400);
        }

        $user->clearTotp();

        // The device holding that authenticator must log in again.
        AuthTokens::revokeFor($user->username);

        Log::info('admin.authenticator_cleared', [
            'by' => $request->user()->username,
            'username' => $user->username,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Authenticator cleared for ' . $user->username,
        ]);
    }
}

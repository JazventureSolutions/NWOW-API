<?php

namespace App\Http\Middleware;

use Closure;

class RequireAdmin
{
    /**
     * Only the super admin role may pass.
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $user = $request->user();

        if (!$user || $user->role !== 'admin') {
            return response()->json(['message' => 'Admin access required'], 403);
        }

        return $next($request);
    }
}

<?php
declare(strict_types=1);

namespace Flynn314\SimpleAuth\Middleware;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;

final class SimpleAuth
{
    public function handle(Request $request, \Closure $next): Response|JsonResponse
    {
        if (!env('FLYNN_SIMPLE_AUTH')) {
            Log::alert('Flynn simple auth is used but token not configured');
            abort(JsonResponse::HTTP_FORBIDDEN);
        }

        if ('127.0.0.1' !== $request->ip() && $request->bearerToken() !== env('FLYNN_SIMPLE_AUTH')) {
            abort(JsonResponse::HTTP_FORBIDDEN);
        }

        return $next($request);
    }
}

<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request): JsonResponse
    {
        $rules = [
            'email' => 'required|email:rfc',
            'password' => 'required'
        ];
        $message = [
            'required' => ':attribute tidak boleh kosong',
            'email' => ':attribute tidak valid'
        ];

        $validator = Validator::make($request->all(), $rules, $message);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'failed',
                'message' => $validator->messages()
            ], 400);
        }

        $credentials = request(['email', 'password']);
        $attemptData = Arr::add($credentials, 'status', 'aktif');

        if (!Auth::attempt($credentials)) {
            $response = response()->json([
                'status' => "failed",
                'message' => 'Unauthorized'
            ], 401);
            return $response;
        }

        $user = User::where('email', $request->input('email'))->first();
        if (!Hash::check($request->input('password'), $user->password, [])) {
            $response = response()->json([
                'status' => "failed",
                'message' => 'Unauthorized'
            ], 401);
            return $response;
        }

        $tokenResult = $user->createToken('token-auth')->plainTextToken;

        $response = response()->json([
            'status' => 'success',
            'data' => [
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
            ]
        ], 200);

        return $response;
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
        $user->currentAccessToken()->delete();
        $response = response()->json([
            'status' => 'success',
            'message' => 'successfully logout'
        ], 200);

        return $response;
    }
}

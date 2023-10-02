<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // Validate incoming request
        $this->validate($request, [
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        $credentials = $request->only(['username', 'password']);
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }
        // Jika otentikasi berhasil, Anda dapat memberikan respons yang sesuai tanpa menghasilkan token JWT
        return $this->respondWithToken($token);
    }



    public function register(Request $request)
    {
        $this->validate($request, [
            'username' => 'required|unique:users',
            'password' => 'required',
        ]);

        $username = $request->input('username');
        $password = Hash::make($request->input('password'));
        $timesTamps = Carbon::now();


        // $data= User::created(['username'=> $username, 'password'=> $password]);
        $query = "INSERT INTO users (username, password, created_at, updated_at) VALUES (?, ?,?,?)";
        $data = DB::insert($query, [$username, $password, $timesTamps, $timesTamps]);

        return response()->json([
            'status_code' => 201, 'data' => $data,
            'message' => 'Akun berhasil ditambahkan'
        ]);
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $user = Auth::user();
        $oauthToken = $user->tokens->where('revoked', false)->first();

        if ($oauthToken) {
            $newToken = $oauthToken->refresh();
            return $this->respondWithToken($newToken);
        }

        return response()->json(['message' => 'Token not found'], 401);
    }
    protected function respondWithToken($token)
    {

        // Mendapatkan waktu saat ini
        $currentTime = Carbon::now();

        // Menambahkan 5 menit ke waktu saat ini
        $expiresAt = $currentTime->addMinutes(5);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_at' => $expiresAt->toDateTimeString(), // Menggunakan waktu kadaluwarsa yang telah dihitung
        ]);
    }
}      
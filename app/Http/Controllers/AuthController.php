<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\User;
use Hash;

class AuthController extends Controller
{

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $user = User::where('email', '=', $request->email)->first();
        $credentials = request(['email', 'password']);
        
        if(empty($user)){
            return response()->json(['error' => 'Email incorrecto.'], 404);
        }else{
            if (Hash::check($request->password, $user->password)) {
                $token = auth()->attempt($credentials);
                $user->attempts = 0;
                $user->save();
                return $this->respondWithToken($token);
            }else if($user->attempts > 5){
                return response()->json(['error' => 'Error, demasiados intentos.'], 401);
            }else{
                $user->attempts += 1;
                $user->save();
                return response()->json(['error' => 'Contraseña incorrecta.'], 401);
            }
        }
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
    public function logout(){
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(){
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

}
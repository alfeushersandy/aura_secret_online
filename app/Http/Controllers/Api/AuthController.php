<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Customer;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * __construct
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api')->except(['register', 'login']);
    }
    /**
     * register
     *
     * @param  mixed $request
     * @return void
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:customers',
            'password' => 'required|confirmed'
        ]);

        if($validator->fails()){
            return response()->json($validator->errors(), 400);
        }

        $customer = Customer::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = JWTAuth::fromUser($customer);

        if($customer){
            return response()->json([
                'success' => true,
                'user' => $customer,
                'token' => $token
            ]);
        }

        return response()->json([
            'success' => false,
        ],400);
    }

    /**
     * login
     *
     * @param  mixed $request
     * @return void
     */

     public function login(Request $request)
     {
        $validator = Validator::make($request->all(),[
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if($validator->fails()){
            return response()->json($validator->errors(), 400);
        }

        $credential = $request->only('email', 'password');

        if(!$token = auth()->guard('api')->attempt($credential)){
            return response()->json([
                'success' => false,
                'message' => 'email atau password anda tidak benar',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'user' => auth()->guard('api')->user(),
            'token' => $token
        ]);
     }

     /**
     * getUser
     *
     * @return void
     */

    public function getUser()
    {
        return response()->json([
            'success' => true,
            'user' => auth()->user()
        ], 200);
    }
}

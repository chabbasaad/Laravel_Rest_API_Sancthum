<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\PostController;
use  App\Http\Controllers\Api\AuthController;
use  App\Http\Controllers\Api\StudentController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::post('/auth/register', [AuthController::class, 'createUser']);
Route::post('/auth/login', [AuthController::class, 'loginUser']);
Route::post('/auth/logout', [AuthController::class, 'logoutUser']);


Route::apiResource('posts', PostController::class)->middleware('auth:sanctum');
// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

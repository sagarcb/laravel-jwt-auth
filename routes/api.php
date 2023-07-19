<?php


use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;


Route::controller(AuthController::class)->group(function () {
    Route::post('login', 'login');
    Route::post('register', 'register');
    Route::post('logout', 'logout');
    Route::post('refresh', 'refresh');
});

Route::controller(AuthController::class)->middleware('jwt.auth')->prefix('api')->group(function () {
    Route::get('hello', 'hello');
});

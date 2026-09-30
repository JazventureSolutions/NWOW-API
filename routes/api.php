<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

/*
|--------------------------------------------------------------------------
| Public - legacy reporting endpoints
|--------------------------------------------------------------------------
*/
Route::get('Login', 'HomeController@Login');
Route::get('LowQuality', 'HomeController@LowQuality');
Route::get('ProductBalance', 'HomeController@ProductBalance');
Route::get('TrialBalance', 'HomeController@TrialBalance');
Route::get('StockTransfer', 'HomeController@StockTransfer');
Route::get('CashBookLedger', 'HomeController@CashBookLedger');
Route::get('products', 'HomeController@getproducts');
Route::post('zagerorder', 'HomeController@Zager');
Route::post('suggestedPrice','HomeController@getSuggested');

/*
|--------------------------------------------------------------------------
| Public - session
|--------------------------------------------------------------------------
*/
Route::post('login', 'AuthController@login');

/*
|--------------------------------------------------------------------------
| Public - forgot password (proves identity with Google Authenticator)
|--------------------------------------------------------------------------
|
| The 6-digit code mints a short-lived, single-use reset token. Wrong
| codes are rate limited and lock the account for 15 minutes.
|
*/
Route::post('totp/verify', 'TotpController@verify');
Route::post('password/reset', 'TotpController@reset');

/*
|--------------------------------------------------------------------------
| Logged in
|--------------------------------------------------------------------------
*/
Route::middleware('auth.token')->group(function () {
    Route::post('logout', 'AuthController@logout');
    Route::get('me', 'AuthController@me');
    Route::post('password/change', 'AuthController@change');
    Route::post('login/verify', 'TotpController@verifyLogin');

    Route::post('totp/setup', 'TotpController@setup');
    Route::post('totp/confirm', 'TotpController@confirm');
    Route::post('totp/status', 'TotpController@status');
    Route::post('totp/disable', 'TotpController@disable');
});

/*
|--------------------------------------------------------------------------
| Super admin only
|--------------------------------------------------------------------------
*/
Route::middleware(['auth.token', 'admin'])->group(function () {
    Route::get('admin/users', 'AdminUserController@index');
    Route::post('admin/users', 'AdminUserController@store');
Route::put('admin/users/{id}', 'AdminUserController@update');
Route::delete('admin/users/{id}', 'AdminUserController@destroy');
    Route::post('admin/users/{id}/reset-password', 'AdminUserController@resetPassword');
    Route::post('admin/users/{id}/clear-authenticator', 'AdminUserController@clearAuthenticator');
});

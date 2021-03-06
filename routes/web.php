<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

//Route::get('/home', 'HomeController@index')->name('home');

Route::get('login/admin', 'Auth\LoginController@showAdminLoginForm');
Route::get('login/customer', 'Auth\LoginController@showCustomerLoginForm');
Route::get('register/admin', 'Auth\RegisterController@showAdminRegisterForm');
Route::get('register/customer', 'Auth\RegisterController@showCustomerRegisterForm');

Route::post('login/admin', 'Auth\LoginController@adminLogin');
Route::post('login/customer', 'Auth\LoginController@customerLogin');
Route::post('register/admin', 'Auth\RegisterController@createAdmin');
Route::post('register/customer', 'Auth\RegisterController@createCustomer');

Route::view('/home', 'home')->middleware('auth');
Route::view('/admin', 'admin');
Route::view('/customer', 'customer');
# laravel-multi-auth
Multiple Authentication: With Guards

Prerequisites
1.	PHP (version >= 7.1.3).
2.	Laravel (version >=5.4).
3.	Composer is installed (version >= 1.3.2).
4.	Laravel installer is installed


Getting started
We will create a Laravel app that has three user classes — admin, customer, user. We will make guards for the three user classes and restrict different parts of our application based on those guards.

Create the application
`$ composer create-project –prefer-dist laravel/laravel multi-auth “5.5.*”`


In app/Providers/AppServiceProvider.php,
```
<?php

...
use Illuminate\Support\Facades\Schema;
...

class AppServiceProvider extends ServiceProvider
{
...
    public function boot()
    {
        Schema::defaultStringLength(191);
    } 
...
}
```
Create the database
Here, MySQL database used. Create database and add into .env file
```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=multiauth
DB_USERNAME=root
DB_PASSWORD=''
```
Creating Model, Controller & Migrations
We will need two classes, the admins and customers, as well as Laravel comes with a users migration.
Create Admin: ``` $php artisan make:model Admin -mcr ```
Create Customer: ``` $php artisan make:model Customer -mcr ```
This command will create the models, controllers and migration files all together.
Migration
Migration for Admins
From the database/migrations directory, open the admins migrations file and edit it as follows: (as personal choice)
//database/migrations/<timestamp>_create_admins_table.php
We have created a simple migration and defined the columns we want the admin table to have. Eloquent provides methods that represent datatypes of our database table. We use them to define the datatypes of our table columns.

```    
    public function up()
    {
        Schema::create('admins', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('is_admin')->default(false);
            $table->rememberToken();
            $table->timestamps();
        });
    } 
...
```
Migration for Customers
From the database/migrations directory, open the customers migrations file and edit it as follows:
//database/migrations/<timestamp>_create_customers_table.php

```
    public function up()
    {
        Schema::create(customers, function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->boolean('is_customer')->default(false);
            $table->rememberToken();
            $table->timestamps();
        });
    } 
...
```
Migrate Database: $php artisan migrate 

Models
Different classes of users will use different database tables for authentication. For this, we have to define different user model which extends the Authenticable class.
Admin model
In app/Admin.php edit as following:
```
<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class Admin extends Authenticatable
{
    use Notifiable;

    protected $guard = 'admin';

    protected $fillable = ['name', 'email', 'password',];
    protected $hidden = [ 'password', 'remember_token',];
}
```
For different users, we need different guards. Here we include admin guard. We will define these guards later.
Customer model
In app/Customer.php edit as following:
```
<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class Customer extends Authenticatable
{
    use Notifiable;

    protected $guard = 'customer';

    protected $fillable = [ 'name', 'email', 'password', ];

    protected $hidden = [ 'password', 'remember_token', ];
}
```
For different users, we need different guards. Here we include admin guard. We will define these guards later

Define guards
To define the guards that added in model files, in config/auth.php edit as following:
```
...
'guards' => [
    ...

    'admin' => [
        'driver' => 'session',
        'provider' => 'admins',
    ],

    'customer' => [
        'driver' => 'session',
        'provider' => 'customers',
    ],

...
    
],
...

// Then add these guards in providers array

'providers' => [
    ...
    'admins' => [
        'driver' => 'eloquent',
        'model' => App\Admin::class,
    ],

    'customers' => [
        'driver' => 'eloquent',
        'model' => App\Customer::class,
    ],
...
],
```

Driver is set to be eloquent since we are using Eloquent ORM as our database manager.


Controllers
Modify LoginController
In app/Http/Controllers/Auth/ LoginController:
```
...
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request; 
use Auth;
class LoginController extends Controller 
{
    use AuthenticatesUsers;
...
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('guest:admin')->except('logout');
        $this->middleware('guest:customer')->except('logout');
    }
}
```
We set these middleware to restrict access to this controller or its methods. By this, if one type of user is already logged in and another user type try to log in, it will redirect to a predefined authentication page for another user. So session doesn’t mess up information.
Login for admins: 
In app/Http/Controllers/Auth/ LoginController:

```
...
class LoginController extends Controller 
{
...
// To show login form for admin
    public function showAdminLoginForm()
    {
        return view('auth.login', ['url' => 'admin']);
    }
// Login functionalities for admin
    public function adminLogin(Request $request)
    {
        $this->validate($request, [
            'email'   => 'required|email',
            'password' => 'required|min:6'
        ]);


        if (Auth::guard('admin')->attempt(['email' => $request->email, 'password' => $request->password],
            $request->get('remember'))) {

            return redirect()->intended('/admin');
        }
        return back()->withInput($request->only('email', 'remember'));
    }
...
}
```
Login for customers: 
In app/Http/Controllers/Auth/ LoginController:
```
...

// To show login form for customer
    public function showCustomerLoginForm()
    {
        return view('auth.login', ['url' => 'customer']);
    }


// Login functionalities for admin
    public function customerLogin(Request $request)
    {
        $this->validate($request, [
            'email'   => 'required|email',
            'password' => 'required|min:6'
        ]);

        if (Auth::guard('customer')->attempt(['email' => $request->email,
            'password' => $request->password], $request->get('remember'))) {

            return redirect()->intended('/customer');
        }
        return back()->withInput($request->only('email', 'remember'));
    }
...
```
Modify RegisterController
In app/Http/Controllers/Auth/ RegisterController:
```
<?php

namespace App\Http\Controllers\Auth;
use App\User;
use App\Admin;
use App\Customer;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;

class RegisterController extends Controller
{ 
  ...  
    public function __construct()
    {
        $this->middleware('guest');
        $this->middleware('guest:admin');
        $this->middleware('guest:customer');
    }
    ...
}
```
Registration for Admins:
In app/Http/Controllers/Auth/ RegisterController:
 
```
class RegisterController extends Controller
{ 
  ...  
// To show registration form for admin
    public function showAdminRegisterForm()
    {
        return view('auth.register', ['url' => 'admin']);
    }
// Registration submit for admin
    protected function createAdmin(Request $request)
    {
        $this->validator($request->all())->validate();
        $admin = Admin::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
        ]);
        return redirect()->intended('login/admin');
    }
...

}
```
Registration for Customers:
In app/Http/Controllers/Auth/ RegisterController:
 
```
class RegisterController extends Controller
{ 
  ...  
// To show registration form for admin
    public function showCustomerRegisterForm()
    {
        return view('auth.register', ['url' => 'customer']);
    }

// Registration submit for customer
    protected function createCustomer(Request $request)
    {
        $this->validator($request->all())->validate();
        $customer = Customer::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
        ]);
        return redirect()->intended('login/customer');
    }
}
```

Authentication pages
This will create authentication pages:
Create Auth: $php artisan make:auth

It creates view files in resources/views/auth along with routes to handle basic authentication. 
Edit the resources/views/auth/login.blade.php file and as follows:
```
...
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">{{ isset($url) ? ucwords($url) : ""}} {{ __('Login') }}</div>
                <div class="panel-body">
                    @isset($url)
                        <form class="form-horizontal"
                              method="POST" action='{{ url("login/$url") }}' aria-label="{{ __('Login') }}">
                    @else
                        <form class="form-horizontal"
                              method="POST" action="{{ route('login') }}" aria-label="{{ __('Login') }}">
                    @endisset
                        {{ csrf_field() }} 
 ... ... ... ... ... ... ... ... ... ... ...
                    </form>
...
</div>
...
```
Here, a checking is used to pass a url parameter to the page when we called it, to modify the forms action to use the url parameter and also modifying the header of the form so that it shows the type of user based on respective login parameter. Same goes for register views.
Edit the resources/views/auth/register.blade.php file and as follows:
```
... 
<div class="container">
    <div class="row">
        <div class="col-md-8 col-md-offset-2">
            <div class="panel panel-default">
                <div class="panel-heading">{{ isset($url) ? ucwords($url) : ""}} {{ __('Register') }}</div>

                <div class="panel-body">
                    @isset($url)
                        <form class="form-horizontal"
                              method="POST" action='{{ url("register/$url") }}' aria-label="{{ __('Register') }}">
                    @else
                        <form class="form-horizontal"
                              method="POST" action="{{ route('register') }}" aria-label="{{ __('Register') }}">
                    @endisset
                        {{ csrf_field() }}
... ... ... ... ... ... ... ... ... ... ...
                    </form>
...
</div>
...
```
Create authenticated page for users access
Create following files (if not exists already):
```
resources/views/layouts/auth.blade.php
resources/views/admin.blade.php
resources/views/customer.blade.php
resources/views/home.blade.php
```
In resources/views/layouts/auth.blade.php:
```
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Laravel') }}</title>

    <!-- Scripts -->
    <script src="{{ asset('js/app.js') }}" defer></script>

    <!-- Fonts -->
    <link rel="dns-prefetch" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css">

    <!-- Styles -->
    <link href="{{ asset('css/app.css') }}" rel="stylesheet">
</head>
<body>
<div id="app">
    <nav class="navbar navbar-expand-md navbar-light navbar-laravel">
        <div class="container">
            <a class="navbar-brand" href="{{ url('/') }}">
                {{ config('app.name', 'Laravel') }}
            </a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="{{ __('Toggle navigation') }}">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <!-- Left Side Of Navbar -->
                <ul class="navbar-nav mr-auto">

                </ul>

                <!-- Right Side Of Navbar -->
                <ul class="navbar-nav ml-auto">
                    <!-- Authentication Links -->
                    <li class="nav-item dropdown">
                        <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                            Hi There <span class="caret"></span>
                        </a>

                        <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                            <a class="dropdown-item" href="{{ route('logout') }}"
                               onclick="event.preventDefault();
                                                     document.getElementById('logout-form').submit();">
                                {{ __('Logout') }}
                            </a>

                            <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                {{ csrf_field() }}
                            </form>
                        </div>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="py-4">
        @yield('content')
    </main>
</div>
</body>
</html>
```
In resources/views/admin.blade.php:
```
@extends('layouts.auth')

@section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Dashboard</div>
                    <div class="card-body">
                        Hi Admin!
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
```
In resources/views/customer.blade.php:
```
@extends('layouts.auth')

@section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Dashboard</div>

                    <div class="card-body">
                        Hi there, awesome customer
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection
```

Routes
Create following files (if not exists already): In routes/web.php:
```
<?php

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

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
```

Modify redirection if authenticated
Laravel by default redirects all authenticated users to /home. If we do not modify the redirection, we will get error:

To solve that, edit app/Http/Middleware/RedirectIfAuthenticated.php file like this:

```
...

class RedirectIfAuthenticated
{
    public function handle($request, Closure $next, $guard = null)
    {
        if ($guard == "admin" && Auth::guard($guard)->check()) {
            return redirect('/admin');
        }
        if ($guard == "customer" && Auth::guard($guard)->check()) {
            return redirect('/customer');
        }
        if (Auth::guard($guard)->check()) {
            return redirect('/home');
        }

        return $next($request);
    }
}

```

Modify authentication exception handler
In app/Exceptions/Handler.php,
```
<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Auth\AuthenticationException;
use Auth;
...
class Handler extends ExceptionHandler
{
...
    protected function unauthenticated($request, AuthenticationException $exception)
    {
        if ($request->expectsJson()) {
            return response()->json(['error' => 'Unauthenticated.'], 401);
        }
        if ($request->is('admin') || $request->is('admin/*')) {
           return redirect()->guest('/login/admin');
        }
        if ($request->is('customer') || $request->is('customer/*')) {
            return redirect()->guest('/login/customer');
     }
     return redirect()->guest(route('login'));
   }
}
```
Now, we can run the application


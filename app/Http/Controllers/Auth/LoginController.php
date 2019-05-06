<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Http\Request;
use Illuminate\Cache\RateLimiter;

use Auth;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('guest:admin')->except('logout');
        $this->middleware('guest:customer')->except('logout');
    }

//    protected function hasTooManyLoginAttempts(Request $request){
//        $minutes = 3;
//        $key = $this->throttleKey($request);
//        $rateLimiter = $this->limiter();
//
//        $attempts = $rateLimiter->attempts($key);
//
//        for ($i = 0; $i < $attempts; $i++) {
//            $this->incrementLoginAttempts($request);
//        }


//    }
    public function showAdminLoginForm()
    {
        return view('auth.login', ['url' => 'admin']);
    }

    public function adminLogin(Request $request)
    {
        $this->validate($request, [
            'email'   => 'required|email',
            'password' => 'required|min:6'
        ]);

//        $minutes = 3;
//        $key = $this->throttleKey($request);
//        $rateLimiter = $this->limiter();
        if ($this->hasTooManyLoginAttempts($request)) {
            $attempt = $this->limiter()->attempts($this->throttleKey($request));
//            if($attempt==3){
                return $this->limiter()->tooManyAttempts(
                    $this->throttleKey($request), 3, 2
                );
//            }elseif ($attempt==5){
//                return $this->limiter()->tooManyAttempts(
//                    $this->throttleKey($request), 5, 3
//                );
//            }
//            $rateLimiter = $this->limiter();
//            $attempts = $rateLimiter->attempts($key);
//            $rateLimiter->clear($key);
//            $this->decayMinutes = $attempts === 1 ? 1 : ($attempts - 1) * $minutes;
//
//            for ($i = 0; $i < $attempts; $i++) {
//                $this->incrementLoginAttempts($request);
//            }

//            $this->fireLockoutEvent($request);
//            return $this->sendLockoutResponse($request);
        }


        if (Auth::guard('admin')->attempt(['email' => $request->email, 'password' => $request->password],
            $request->get('remember'))) {

            return redirect()->intended('/admin');
        }
        return back()->withInput($request->only('email', 'remember'));
    }

    public function showCustomerLoginForm()
    {
        return view('auth.login', ['url' => 'customer']);
    }

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

}

<?php

namespace App;

use App\Models\TotpBackupCode;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Cache;

class User extends Authenticatable
{
    use Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password', 'username', 'role',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token', 'totp_secret',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'totp_confirmed_at' => 'datetime',
        'totp_last_used_at' => 'datetime',
        'totp_locked_until' => 'datetime',
        'totp_attempts' => 'integer',
    ];

    /**
     * One-time recovery codes for this account.
     */
    public function backupCodes()
    {
        return $this->hasMany(TotpBackupCode::class, 'user_id');
    }

    /**
     * True once the user has activated Google Authenticator.
     */
    public function hasTotp()
    {
        return !is_null($this->totp_confirmed_at) && !empty($this->totp_secret);
    }

    /**
     * Unbind Google Authenticator from this account and drop its backup codes.
     */
    public function clearTotp()
    {
        $this->totp_secret = null;
        $this->totp_confirmed_at = null;
        $this->totp_last_code = null;
        $this->totp_last_used_at = null;
        $this->totp_attempts = 0;
        $this->totp_locked_until = null;
        $this->save();

        $this->backupCodes()->delete();

        Cache::forget('totp_lock:' . $this->username);
        Cache::forget('totp_fail:' . $this->username);
    }
}

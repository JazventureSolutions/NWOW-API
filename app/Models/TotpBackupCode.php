<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class TotpBackupCode extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'user_id', 'code_hash', 'used_at',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'code_hash',
    ];

    protected $casts = [
        'used_at' => 'datetime',
    ];
}

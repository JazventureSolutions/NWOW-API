<?php

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        // Mobile app super admin.
        if (!\App\User::where('username', 'junaid')->exists()) {
            \App\User::create([
                'name' => 'Junaid',
                'username' => 'junaid',
                'email' => 'junaid@nwow.local',
                'password' => Hash::make('nwowjunaidapi'),
                'role' => 'admin',
            ]);
        }

        // Never demote the owner account, whatever happened before.
        \App\User::where('username', 'junaid')->update(['role' => 'admin']);
    }
}

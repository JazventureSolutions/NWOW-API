<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddTotpToUsersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('username')->nullable()->unique()->after('name');
            $table->text('totp_secret')->nullable()->after('password');
            $table->timestamp('totp_confirmed_at')->nullable()->after('totp_secret');
            $table->timestamp('totp_last_used_at')->nullable()->after('totp_confirmed_at');
            $table->string('totp_last_code', 8)->nullable()->after('totp_last_used_at');
            $table->unsignedInteger('totp_attempts')->default(0)->after('totp_last_code');
            $table->timestamp('totp_locked_until')->nullable()->after('totp_attempts');
        });

        Schema::create('totp_backup_codes', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('user_id');
            $table->string('code_hash', 64);
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->index('user_id');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('totp_backup_codes');

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'username', 'totp_secret', 'totp_confirmed_at',
                'totp_last_used_at', 'totp_last_code', 'totp_attempts', 'totp_locked_until',
            ]);
        });
    }
}

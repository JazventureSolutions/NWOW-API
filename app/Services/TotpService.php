<?php

namespace App\Services;

/**
 * Dependency-free RFC 6238 TOTP implementation.
 * No composer package required, so only app/ files need re-uploading.
 */
class TotpService
{
    const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** @var int */
    private $digits;

    /** @var int */
    private $period;

    public function __construct($digits = 6, $period = 30)
    {
        $this->digits = (int) $digits;
        $this->period = (int) $period;
    }

    /**
     * Random base32 secret (20 bytes = 32 chars, the Google Authenticator default).
     */
    public function generateSecret($bytes = 20)
    {
        return $this->base32Encode(random_bytes($bytes));
    }

    /**
     * otpauth:// URI that Google Authenticator understands.
     */
    public function getOtpauthUrl($secret, $account, $issuer = 'NWOW')
    {
        return 'otpauth://totp/'
            . rawurlencode($issuer) . ':' . rawurlencode($account)
            . '?secret=' . urlencode($secret)
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1'
            . '&digits=' . $this->digits
            . '&period=' . $this->period;
    }

    /**
     * The code that should be showing in the authenticator right now.
     */
    public function getCode($secret)
    {
        $key = $this->base32Decode($secret);
        if ($key === null || $key === '') {
            return '';
        }

        return $this->generateAt($key, (int) floor(time() / $this->period));
    }

    /**
     * Accepts the previous/current/next window (90 seconds of drift).
     */
    public function verify($secret, $code)
    {
        $code = preg_replace('/\s+/', '', (string) $code);
        if (!preg_match('/^\d{' . $this->digits . '}$/', $code)) {
            return false;
        }

        $key = $this->base32Decode($secret);
        if ($key === null || $key === '') {
            return false;
        }

        $counter = (int) floor(time() / $this->period);
        for ($i = -1; $i <= 1; $i++) {
            if (hash_equals($this->generateAt($key, $counter + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * One-time recovery codes, shown once at enrolment.
     *
     * @return array
     */
    public function generateBackupCodes($count = 10)
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $raw = bin2hex(random_bytes(5));
            $codes[] = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
        }

        return $codes;
    }

    public static function hashBackupCode($code)
    {
        return hash('sha256', strtoupper(str_replace('-', '', preg_replace('/\s+/', '', (string) $code))));
    }

    private function generateAt($key, $counter)
    {
        if ($counter < 0) {
            $counter = 0;
        }

        $bin = pack('N2', 0, $counter);
        $hash = hash_hmac('sha1', $bin, $key, true);
        $offset = ord($hash[19]) & 0x0f;

        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | ((ord($hash[$offset + 1]) & 0xff) << 16)
            | ((ord($hash[$offset + 2]) & 0xff) << 8)
            | (ord($hash[$offset + 3]) & 0xff);

        return str_pad((string) ($value % pow(10, $this->digits)), $this->digits, '0', STR_PAD_LEFT);
    }

    private function base32Encode($data)
    {
        if ($data === '' || $data === null) {
            return '';
        }

        $binary = '';
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $binary .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($binary, 5) as $chunk) {
            $out .= self::B32[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $out;
    }

    private function base32Decode($input)
    {
        $input = strtoupper(str_replace([' ', '-'], '', trim((string) $input)));
        $input = rtrim($input, '=');
        if ($input === '') {
            return null;
        }

        $map = array_flip(str_split(self::B32));
        $binary = '';
        foreach (str_split($input) as $char) {
            if (!isset($map[$char])) {
                return null;
            }
            $binary .= str_pad(decbin($map[$char]), 5, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($binary, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $out .= chr(bindec($chunk));
            }
        }

        return $out;
    }
}

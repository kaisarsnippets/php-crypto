<?php
/**
 * Class Crypto provides methods for encrypting and decrypting strings.
 */
class Crypto {

    /**
     * Encrypts a given string using AES encryption with salt and hexadecimal encoding.
     *
     * @param string $str The string to encrypt.
     * @param string $pwd The password to use for encryption.
     * @return string|false The encrypted string, or false if encryption fails.
     */
    public static function encrypt($str, $pwd){
        $out = false;
        try {
            $mth = 'aes-256-cbc';
            $pwd = sha1($pwd);
            $ivl = openssl_cipher_iv_length($mth);
            $iv  = random_bytes($ivl);
            $iv = str_replace(":",".",$iv);
            $slt = sha1(random_bytes(32));
            $pws = hash('sha256', $pwd.$slt);
            $pwc = openssl_encrypt($str, $mth, $pws, 0, $iv);
            $out = "$iv:$slt:$pwc";
            $out = urlencode($out);
            $out = bin2hex($out);
        } catch (Exception $e) { }
        return $out;
    }

    /**
     * Decrypts a given string that was encrypted using AES encryption with salt and hexadecimal encoding.
     *
     * @param string $str The string to decrypt.
     * @param string $pwd The password to use for decryption.
     * @return string|false The decrypted string, or false if decryption fails.
     */
    public static function decrypt($str, $pwd){
        $out = false;
        try {
            $mth = 'aes-256-cbc';
            $pwd = sha1($pwd);
            $str = hex2bin($str);
            $str = urldecode($str);
            $cmp = explode(':', $str);
            if (count($cmp) >= 3) {
                $iv  = $cmp[0];
                $slt = $cmp[1];
                $txt = $cmp[2];
                $pws = hash('sha256', $pwd.$slt);
                $pwc = openssl_decrypt($txt, $mth, $pws, 0, $iv);
                $out = $pwc;
            }
        } catch (Exception $e) { }
        return $out;
    }
}

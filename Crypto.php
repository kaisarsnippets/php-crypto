<?php
Class Crypto {
    
    // Encrypt AES + Salt + HEX
    static function encrypt($str, $pwd){
        $out = false;
        try {
        $pwd = sha1($pwd);
        $iv  = random_bytes(16);
        $slt = sha1(random_bytes(32));
        $pws = hash('sha256', $pwd.$slt);
        $mth = 'aes-256-cbc';
        @$pwc = openssl_encrypt($str, $mth, $pws, null, $iv);
        $out = "$iv:$slt:$pwc";
        $out = bin2hex($out);
        } catch (Exception $e) {}
        return $out;
    }
    
    // DECRYPT AES + SALT + HEX
    public function decrypt($str, $pwd)
    {
        $out = false;
        try {
        $pwd = sha1($pwd);
       @$str = hex2bin($str);
        $cmp = explode(':', $str);
        if (count($cmp) >= 3) {
        $iv  = $cmp[0];
        $slt = $cmp[1];
        $txt = $cmp[2];
        $pws = hash('sha256', $pwd.$slt);
        $mth = 'aes-256-cbc';
       @$pwc = openssl_decrypt($txt, $mth, $pws, null, $iv);
        $out = $pwc;
        }} catch (Exception $e) {}
        return $out;
    }
}

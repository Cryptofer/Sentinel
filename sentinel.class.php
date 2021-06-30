<?php

/*
    Title: Sentinel
    Description:
    A very basic PHP-based DDoS protection class
*/

class Sentinel {
    
    protected $Checksum; // Symmetrically encrypted checksum of our user's data
    protected $uidToken; // Cryptographically secure random string for additional identification

    protected $timeAlive = 3600; //0 Representing unlimited
    protected $Cipher = "AES-128-CTR";

    public function __construct() {
        
        //Get the random auth token 
        if(isset($_COOKIE['sentinel_uid'])) {
            $this->uidToken = $_COOKIE['sentinel_uid'];
        }

        if(isset($_COOKIE['sentinel_checksum'])) {
            $this->Checksum = $_COOKIE['sentinel_checksum'];
        }

        //setcookie('sentinel_auth', $key, time() + (86400 * 1), "/");
    }

    public function validateSession() {
    
        if(empty($this->Checksum) || empty($this->uidToken)) {
            return false;
        }

        //Get our user's fingerprint
        $Fingerprint = $this->getFingerprint($this->uidToken);

        //Decrypt our checksum with our private key as well as the visitor uid token
        //Validate the decryption by checking whether the string contains 'success' in the beginning.
        $decryptedChecksum = $this->decrypt($this->Checksum, (constant("SENTINEL_SECRET") . $this->uidToken));
        if(!substr($decryptedChecksum, 0, strlen('success')) == "success") {
            return false;
        }

        // Split our decrypted string to validate the values we have stored within them.
        $splitKeys = explode('|', $decryptedChecksum);

        // Match the fingerpint of the token, that it is in fact exactly the same as the current visitor.
        if(empty($splitKeys[1]) || $splitKeys[1] !== $Fingerprint) { 
            return false;
        }

        if(empty($splitKeys[2]) || time() > $splitKeys[2]) {
            return false;
        }

        return true;

    }

    public function createSession() {
        
        //Generate the token sets
        $uidToken = $this->generateUID();
        $Fingerprint = $this->getFingerprint($uidToken);
        $expiryTime = time() + $this->timeAlive;

        if(empty($uidToken) || empty($Fingerprint) || empty($expiryTime)) {
            return false;
        }

        $Checksum = $this->encrypt("success|{$Fingerprint}|{$expiryTime}", (constant("SENTINEL_SECRET") . $uidToken));
        if(empty($Checksum)) {
            return false;
        }

        setcookie('sentinel_uid', $uidToken, time() + $this->timeAlive, "/");
        setcookie('sentinel_checksum', $Checksum, time() + $this->timeAlive, "/");

        return true;
    }

    protected function generateUID() {
        //Generate a random uid token
        $uidToken = bin2hex(openssl_random_pseudo_bytes(48));
        if(strlen($uidToken) == 0) {
            return;
        }

        return $uidToken;
    }

    //Generate a sha256 string out the user's current ip address and user agent
    //uidToken is just an external parameter to make it harder for the server to manipulate/read user's data.
    protected function getFingerprint($uidToken) {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $ipAddress = $_SERVER['REMOTE_ADDR'];

        $fingerprint = hash_pbkdf2("sha256", ($userAgent . $ipAddress), $uidToken, 2500, 128);

        return $fingerprint;
    }

    protected function encrypt($data, $secret) {

        $encryption_key = openssl_random_pseudo_bytes(32); 
        $encData = openssl_encrypt($data, $this->Cipher, $secret, 0, constant('SENTINEL_IV')); 

        return base64_encode($encData);
    }

    protected function decrypt($data, $secret) {
        return openssl_decrypt(base64_decode($data), $this->Cipher, $secret, 0, constant('SENTINEL_IV')); 
    }
}

?>
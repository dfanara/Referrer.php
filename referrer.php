<?php

/**
 * Class to encrypt and decrypt the cookies stored.
 * Not required, but generally prevents tampering.
 *
 * If you change the options while running in a production environment,
 * previous cookies will not be able to be read properly.
 *
 * Configure properly for best results.
 * Cookie encryption is suggested, but not required as it may be useful
 * for development environments.
 *
 * Copyright Daniel Fanara 2015.
 * This software is licensed with GNU GPL v3.
 * A full copy of this license can be found at http://choosealicense.com/licenses/gpl-3.0/
 *
 * @author Daniel Fanara
 * @version 1.0
 */
class Referrer
{

    /**
     * Passphrase used for encrypting the cookies, if encryption in enabled.
     * !#! SET TO A RANDOM 16-64 CHARACTER RANDOM STRING !#!
     */
    private $passphrase = "r4nd0m p455phr453 f0r 3ncryp71n6 c00k135, 1f 3n4bl3d";

    /**
     * Salt for verification cookie.
     *
     * !#! SET TO A RANDOM 32-64 CHARACTER RANDOM STRING !#!
     *     The longer the string the more secure the salt.
     *
     * Cannot be modified once used, otherwise cookies will not be read if
     * verification is enabled.
     */
    private $salt = "PlEaSe-_-UsE-_-sOmEtHiNg-_-RaNdOm";

    /**
     * SHA256 hashed passphrase.
     */
    private $cryptoKey;

    /**
     * Used in cryptographic functions.
     */
    private $initializationVector;

    /**
     * Should the cookie values be encrypted to prevent tampering?
     */
    private $encryption;

    /**
     * The base name for Cookies storing the original referrer.
     */
    private $name;

    /**
     * Should the cookies contents be verified before decryption?
     * If enabled, two cookies will be created.
     */
    private $verify;

    function __construct($cookiename = "origin", $encryption = true, $verify = true)
    {
        $this->name       = $cookiename;
        $this->encryption = $encryption;
        $this->verify     = $verify;
    }

    /**
     * Check if the crypto-specific variables have been initialized.
     * If not, initialize them.
     */
    private function check_setup()
    {
        if (!isset($this->cryptoKey)) {
            $this->cryptoKey = hash('sha256', $this->passphrase, true);
        }

        if (!isset($this->initializationVector)) {
            $this->initializationVector = mcrypt_create_iv(32);
        }
    }

    private function encrypt($input)
    {
        $this->check_setup();

        return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->cryptoKey, $input, MCRYPT_MODE_ECB, $this->initializationVector));
    }

    private function decrypt($input)
    {
        $this->check_setup();
        return trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->cryptoKey, base64_decode($input), MCRYPT_MODE_ECB, $this->initializationVector));
    }

    /**
     * Check if the cookie is already set.
     * If the cookie is not set and there is an HTTP_REFERER,
     *    Create the cookie.
     * If the cookie already exists,
     *    Do not create a new cookie, as to retain the original referrer.
     */
    public function check_referrer()
    {
        $this->check_setup();
        if (!isset($_COOKIE[$this->name]) && isset($_SERVER['HTTP_REFERER'])) {
            if(strpos($_SERVER['HTTP_REFERER'], $_SERVER['HTTP_HOST']) !== false)
                return; //Do not add the referrer if it is from the same domain.
            $cookie_value = $_SERVER['HTTP_REFERER'];
            if ($this->encryption) {
                //generate the encrypted cookie
                $cookie_value = $this->encrypt($cookie_value);
                setcookie($this->name, $cookie_value, time() + 86400 * 30, "/"); //Set cookie for 30 days.
                $_COOKIE[$this->name] = $cookie_value;
            } else {
                setcookie($this->name, $cookie_value, time() + 86400 * 30, "/"); //Set cookie for 30 days.
                $_COOKIE[$this->name] = $cookie_value;
            }

            if ($this->verify) {
                $cookie_hash = hash('sha256', $cookie_value . $this->salt);
                setcookie($this->name . "_verify", $cookie_hash, time() + 86400 * 30, "/"); //Set verification hash for 30 days.
                $_COOKIE[$this->name . "_verify"] = $cookie_hash;
            }
        }
    }

    /**
     * Retrieves the original referrer from stored cookies.
     *
     * @return string | false. Returns the referrer or false if not set.
     */
    public function retrieve_referrer()
    {
        $this->check_setup();
        if (isset($_COOKIE[$this->name])) {
            $cookie_value     = $_COOKIE[$this->name];
            $encrypted_cookie = $_COOKIE[$this->name];
            if ($this->encryption) {
                //Decrypt the cookie.
                $cookie_value = $this->decrypt($cookie_value);
            }

            if ($this->verify) {
                if (isset($_COOKIE[$this->name . "_verify"])) {
                    //Verify the cookie!
                    $hash                = hash('sha256', $encrypted_cookie . $this->salt);
                    $verification_cookie = $_COOKIE[$this->name . '_verify'];
                    if ($hash == $verification_cookie) {
                        //Verified the cookie successfully.
                        return $cookie_value;
                    } else {
                        return false;
                    }
                } else {
                    //Can't verify the referrer, so return none.
                    return false;
                }
            } else {
                //Don't verify the cookie. (Why not? :( )
                return $cookie_value;
            }
        } else {
            //No referrer found.
            return false;
        }
    }
}

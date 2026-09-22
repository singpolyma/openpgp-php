<?php

/**
 * Aliases phpseclib3 class namespaces to phpseclib4 when phpseclib3 is loaded
 */
if (class_exists('phpseclib3\\Crypt\\AES')) {
    class_alias('phpseclib3\\Crypt\\AES', 'phpseclib4\\Crypt\\AES');
    class_alias('phpseclib3\\Crypt\\Blowfish', 'phpseclib4\\Crypt\\Blowfish');
    class_alias('phpseclib3\\Crypt\\PublicKeyLoader', 'phpseclib4\\Crypt\\PublicKeyLoader');
    class_alias('phpseclib3\\Crypt\\RSA', 'phpseclib4\\Crypt\\RSA');
    class_alias('phpseclib3\\Crypt\\RSA\\Formats\\Keys\\PKCS1', 'phpseclib4\\Crypt\\RSA\\Formats\\Keys\\PKCS1');
    class_alias('phpseclib3\\Crypt\\TripleDES', 'phpseclib4\\Crypt\\TripleDES');
    class_alias('phpseclib3\\Crypt\\TwoFish', 'phpseclib4\\Crypt\\TwoFish');
    class_alias('phpseclib3\\Math\\BigInteger', 'phpseclib4\\Math\\BigInteger');
}
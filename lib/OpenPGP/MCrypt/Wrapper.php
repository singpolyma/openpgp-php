<?php

namespace OpenPGP\MCrypt;

class Wrapper
{
    public $cipher;
    public $key;
    public $iv;
    public $key_size;
    public $block_size;

    public function __construct($cipher)
    {
        $this->cipher = $cipher;
        $this->key_size = mcrypt_module_get_algo_key_size($cipher);
        $this->block_size = mcrypt_module_get_algo_block_size($cipher);
        $this->iv = str_repeat("\0", mcrypt_get_iv_size($cipher, 'ncfb'));
    }

    public function setKey($key)
    {
        $this->key = $key;
    }

    public function setIV($iv)
    {
        $this->iv = $iv;
    }

    public function encrypt($data)
    {
        return mcrypt_encrypt($this->cipher, $this->key, $data, 'ncfb', $this->iv);
    }

    public function decrypt($data)
    {
        return mcrypt_decrypt($this->cipher, $this->key, $data, 'ncfb', $this->iv);
    }
}

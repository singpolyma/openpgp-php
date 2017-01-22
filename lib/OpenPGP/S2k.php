<?php

namespace OpenPGP;

class S2k
{
    public $type;
    public $hash_algorithm;
    public $salt;
    public $count;

    public function __construct($salt='BADSALT', $hash_algorithm=10, $count=65536, $type=3)
    {
        $this->type = $type;
        $this->hash_algorithm = $hash_algorithm;
        $this->salt = $salt;
        $this->count = $count;
    }

    public static function parse(&$input)
    {
        $s2k = new S2k();
        switch ($s2k->type = ord($input{0})) {
            case 0:
                $s2k->hash_algorithm = ord($input{1});
                $input = substr($input, 2);
                break;
            case 1:
                $s2k->hash_algorithm = ord($input{1});
                $s2k->salt = substr($input, 2, 8);
                $input = substr($input, 10);
                break;
            case 3:
                $s2k->hash_algorithm = ord($input{1});
                $s2k->salt = substr($input, 2, 8);
                $s2k->count = OpenPGP::decode_s2k_count(ord($input{10}));
                $input = substr($input, 11);
                break;
        }

        return $s2k;
    }

    public function to_bytes()
    {
        $bytes = chr($this->type);
        switch ($this->type) {
            case 0:
                $bytes .= chr($this->hash_algorithm);
                break;
            case 1:
                $bytes .= chr($this->hash_algorithm);
                $bytes .= $this->salt;
                break;
            case 3:
                $bytes .= chr($this->hash_algorithm);
                $bytes .= $this->salt;
                $bytes .= chr(OpenPGP::encode_s2k_count($this->count));
                break;
        }
        return $bytes;
    }

    public function raw_hash($s)
    {
        return hash(strtolower(OpenPGP_SignaturePacket::$hash_algorithms[$this->hash_algorithm]), $s, true);
    }

    public function sized_hash($s, $size)
    {
        $hash = $this->raw_hash($s);
        while (strlen($hash) < $size) {
            $s = "\0" . $s;
            $hash .= $this->raw_hash($s);
        }

        return substr($hash, 0, $size);
    }

    public function iterate($s)
    {
        if (strlen($s) >= $this->count) {
            return $s;
        }
        $s = str_repeat($s, ceil($this->count / strlen($s)));
        return substr($s, 0, $this->count);
    }

    public function make_key($pass, $size)
    {
        switch ($this->type) {
            case 0:
                return $this->sized_hash($pass, $size);
            case 1:
                return $this->sized_hash($this->salt . $pass, $size);
            case 3:
                return $this->sized_hash($this->iterate($this->salt . $pass), $size);
        }
    }
}

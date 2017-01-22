<?php

namespace OpenPGP\Packet;

/**
 * OpenPGP Public-Key Encrypted Session Key packet (tag 1).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.1
 */
class AsymmetricSessionKeyPacket extends Packet
{
    public $version;
    public $keyid;
    public $key_algorithm;
    public $encrypted_data;

    public function __construct($key_algorithm='', $keyid='', $encrypted_data='', $version=3)
    {
        parent::__construct();
        $this->version = $version;
        $this->keyid = substr($keyid, -16);
        $this->key_algorithm = $key_algorithm;
        $this->encrypted_data = $encrypted_data;
    }

    public function read()
    {
        switch ($this->version = ord($this->read_byte())) {
            case 3:
                $rawkeyid = $this->read_bytes(8);
                $this->keyid = '';
                for ($i = 0; $i < strlen($rawkeyid); $i++) { // Store KeyID in Hex
                    $this->keyid .= sprintf('%02X', ord($rawkeyid{$i}));
                }

                $this->key_algorithm = ord($this->read_byte());

                $this->encrypted_data = $this->input;
                break;
            default:
                throw new \Exception("Unsupported AsymmetricSessionKeyPacket version: " . $this->version);
        }
    }

    public function body()
    {
        $bytes = chr($this->version);

        for ($i = 0; $i < strlen($this->keyid); $i += 2) {
            $bytes .= chr(hexdec($this->keyid{$i}.$this->keyid{$i+1}));
        }

        $bytes .= chr($this->key_algorithm);
        $bytes .= $this->encrypted_data;
        return $bytes;
    }
}

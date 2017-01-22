<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class SignatureTargetPacket extends Subpacket
{
    public $key_algorithm;
    public $hash_algorithm;

    public function read()
    {
        $this->key_algorithm = ord($this->read_byte());
        $this->hash_algorithm = ord($this->read_byte());
        $this->data = $this->input;
    }

    public function body()
    {
        return chr($this->key_algorithm) . chr($this->hash_algorithm) . $this->data;
    }
}

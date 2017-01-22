<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class ReasonforRevocationPacket extends Subpacket
{
    public $code;

    public function read()
    {
        $this->code = ord($this->read_byte());
        $this->data = $this->input;
    }

    public function body()
    {
        return chr($this->code) . $this->data;
    }
}

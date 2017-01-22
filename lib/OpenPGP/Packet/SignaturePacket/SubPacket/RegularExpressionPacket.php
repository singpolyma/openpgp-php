<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class RegularExpressionPacket extends SubPacket
{
    public function read()
    {
        $this->data = substr($this->input, 0, -1);
    }

    public function body()
    {
        return $this->data . chr(0);
    }
}

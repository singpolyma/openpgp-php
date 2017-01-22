<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class RegularExpressionPacket extends SubPacket
{
    function read() {
        $this->data = substr($this->input, 0, -1);
    }

    function body() {
        return $this->data . chr(0);
    }
}

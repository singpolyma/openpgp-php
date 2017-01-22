<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PolicyURIPacket extends Subpacket
{
    function read() {
        $this->data = $this->input;
    }

    function body() {
        return $this->data;
    }
}

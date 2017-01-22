<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PolicyURIPacket extends Subpacket
{
    public function read()
    {
        $this->data = $this->input;
    }

    public function body()
    {
        return $this->data;
    }
}

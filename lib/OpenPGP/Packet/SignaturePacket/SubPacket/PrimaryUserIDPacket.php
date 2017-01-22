<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PrimaryUserIDPacket extends Subpacket
{
    public function read()
    {
        $this->data = (ord($this->input) != 0);
    }

    public function body()
    {
        return chr($this->data ? 1 : 0);
    }
}

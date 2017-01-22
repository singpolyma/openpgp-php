<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class KeyExpirationTimePacket extends Subpacket
{
    public function read()
    {
        $this->data = $this->read_timestamp();
    }

    public function body()
    {
        return pack('N', $this->data);
    }
}

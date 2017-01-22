<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class SignatureExpirationTimePacket extends Subpacket
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

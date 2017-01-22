<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class TrustSignaturePacket extends SubPacket
{
    public function read()
    {
        $this->depth = ord($this->input{0});
        $this->trust = ord($this->input{1});
    }

    public function body()
    {
        return chr($this->depth) . chr($this->trust);
    }
}

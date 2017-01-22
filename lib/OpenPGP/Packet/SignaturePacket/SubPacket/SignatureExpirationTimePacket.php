<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class SignatureExpirationTimePacket extends Subpacket {
    function read() {
        $this->data = $this->read_timestamp();
    }

    function body() {
        return pack('N', $this->data);
    }
}

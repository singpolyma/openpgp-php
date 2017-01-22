<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PrimaryUserIDPacket extends Subpacket {
    function read() {
        $this->data = (ord($this->input) != 0);
    }

    function body() {
        return chr($this->data ? 1 : 0);
    }

}

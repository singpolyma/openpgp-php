<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PreferredKeyServerPacket extends Subpacket {
    function read() {
        $this->data = $this->input;
    }

    function body() {
        return $this->data;
    }
}

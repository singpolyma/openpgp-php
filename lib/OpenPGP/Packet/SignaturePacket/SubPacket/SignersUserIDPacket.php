<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class SignersUserIDPacket extends Subpacket {
    function read() {
        $this->data = $this->input;
    }

    function body() {
        return $this->data;
    }
}

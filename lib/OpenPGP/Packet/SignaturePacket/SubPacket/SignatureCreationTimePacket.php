<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
class SignatureCreationTimePacket extends SubPacket {
    function read() {
        $this->data = $this->read_timestamp();
    }

    function body() {
        return pack('N', $this->data);
    }
}
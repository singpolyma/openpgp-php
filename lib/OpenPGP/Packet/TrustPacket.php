<?php

namespace OpenPGP\Packet;

/**
 * OpenPGP Trust packet (tag 12).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.10
 */
class TrustPacket extends Packet
{
    public function read() {
        $this->data = $this->input;
    }

    public function body() {
        return $this->data;
    }
}
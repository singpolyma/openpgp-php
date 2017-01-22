<?php

namespace OpenPGP\Packet\EncryptedDataPacket;

use OpenPGP\Packet\Packet;

/**
 * OpenPGP Symmetrically Encrypted Data packet (tag 9).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.7
 */
class EncryptedDataPacket extends Packet
{
    function read() {
        $this->data = $this->input;
    }

    function body() {
        return $this->data;
    }
}

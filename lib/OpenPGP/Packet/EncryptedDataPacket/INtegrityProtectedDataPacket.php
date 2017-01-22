<?php

namespace OpenPGP\Packet\EncryptedDataPacket;

/**
 * OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.13
 */
class IntegrityProtectedDataPacket extends EncryptedDataPacket
{
    public $version;

    function __construct($data='', $version=1) {
        parent::__construct();
        $this->version = $version;
        $this->data = $data;
    }

    function read() {
        $this->version = ord($this->read_byte());
        $this->data = $this->input;
    }

    function body() {
        return chr($this->version) . $this->data;
    }
}

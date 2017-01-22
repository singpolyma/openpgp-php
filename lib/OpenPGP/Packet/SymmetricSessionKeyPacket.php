<?php

namespace OpenPGP\Packet;

use OpenPGP\S2k;

/**
 * OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.3
 */
class SymmetricSessionKeyPacket extends Packet
{
    public $version;
    public $symmetric_algorithm;
    public $s2k;
    public $encrypted_data;

    public function __construct($s2k=null, $encrypted_data='', $symmetric_algorithm=9, $version=3)
    {
        parent::__construct();
        $this->version = $version;
        $this->symmetric_algorithm = $symmetric_algorithm;
        $this->s2k = $s2k;
        $this->encrypted_data = $encrypted_data;
    }

    public function read()
    {
        $this->version = ord($this->read_byte());
        $this->symmetric_algorithm = ord($this->read_byte());
        $this->s2k = S2k::parse($this->input);
        $this->encrypted_data = $this->input;
    }

    public function body()
    {
        return chr($this->version) . chr($this->symmetric_algorithm) .
            $this->s2k->to_bytes() . $this->encrypted_data;
    }
}

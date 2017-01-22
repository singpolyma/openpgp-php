<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class PreferredCompressionAlgorithmsPacket extends Subpacket
{
    function read() {
        $this->data = array();
        while(strlen($this->input) > 0) {
            $this->data[] = ord($this->read_byte());
        }
    }

    function body() {
        $bytes = '';
        foreach($this->data as $algo) {
            $bytes .= chr($algo);
        }
        return $bytes;
    }
}

<?php

namespace OpenPGP\Packet;

/**
 * OpenPGP Modification Detection Code packet (tag 19).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.14
 */
class ModificationDetectionCodePacket extends Packet
{
    function __construct($sha1='') {
        parent::__construct();
        $this->data = $sha1;
    }

    function read() {
        $this->data = $this->input;
        if(strlen($this->input) != 20) throw new \Exception("Bad ModificationDetectionCodePacket");
    }

    function header_and_body() {
        $body = $this->body(); // Get body first, we will need it's length
        if(strlen($body) != 20) throw new \Exception("Bad ModificationDetectionCodePacket");
        return array('header' => "\xD3\x14", 'body' => $body);
    }

    function body() {
        return $this->data;
    }
}

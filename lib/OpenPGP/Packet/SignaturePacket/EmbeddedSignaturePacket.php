<?php

namespace OpenPGP\Packet\SignaturePacket;

class EmbeddedSignaturePacket extends SignaturePacket
{
    // TODO: This is duplicated from subpacket... improve?
    public function __construct($data=null)
    {
        parent::__construct($data);
        $this->tag = array_search(substr(substr(get_class($this), 8+16), 0, -6), SignaturePacket::$subpacket_types);
    }

    public function header_and_body()
    {
        $body = $this->body(); // Get body first, we will need it's length
        $size = chr(255).pack('N', strlen($body)+1); // Use 5-octet lengths + 1 for tag as first packet body octet
        $tag = chr($this->tag);
        return array('header' => $size.$tag, 'body' => $body);
    }
}

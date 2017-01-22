<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class KeyServerPreferencesPacket extends Subpacket
{
    public $no_modify;

    public function read()
    {
        $flags = ord($this->input);
        $this->no_modify = $flags & 0x80 == 0x80;
    }

    public function body()
    {
        return chr($this->no_modify ? 0x80 : 0x00);
    }
}

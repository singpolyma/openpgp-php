<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class NotationDataPacket extends Subpacket
{
    public $human_readable;
    public $name;

    public function read()
    {
        $flags = $this->read_bytes(4);
        $namelen = $this->read_unpacked(2, 'n');
        $datalen = $this->read_unpacked(2, 'n');
        $this->human_readable = ord($flags[0]) & 0x80 == 0x80;
        $this->name = $this->read_bytes($namelen);
        $this->data = $this->read_bytes($datalen);
    }

    public function body()
    {
        return chr($this->human_readable ? 0x80 : 0x00) . "\0\0\0" .
            pack('n', strlen($this->name)) . pack('n', strlen($this->data)) .
            $this->name . $this->data;
    }
}

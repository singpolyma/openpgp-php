<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket;

class RevocationKeyPacket extends Subpacket
{
    public $key_algorithm;
    public $fingerprint;
    public $sensitive;

    public function read()
    {
        // bitfield must have bit 0x80 set, says the spec
        $bitfield = ord($this->read_byte());
        $this->sensitive = $bitfield & 0x40 == 0x40;
        $this->key_algorithm = ord($this->read_byte());

        $this->fingerprint = '';
        while (strlen($this->input) > 0) {
            $this->fingerprint .= sprintf('%02X', ord($this->read_byte()));
        }
    }

    public function body()
    {
        $bytes = '';
        $bytes .= chr(0x80 | ($this->sensitive ? 0x40 : 0x00));
        $bytes .= chr($this->key_algorithm);

        for ($i = 0; $i < strlen($this->fingerprint); $i += 2) {
            $bytes .= chr(hexdec($this->fingerprint{$i}.$this->fingerprint{$i+1}));
        }

        return $bytes;
    }
}

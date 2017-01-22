<?php

namespace OpenPGP\Packet\SignaturePacket\SubPacket\KeyFlagsPacket;

use OpenPGP\Packet\SignaturePacket\SubPacket\SubPacket;

class KeyFlagsPacket extends SubPacket
{
    /**
     * @var array
     */
    private $flags;

    public function __construct($flags=array())
    {
        parent::__construct();
        $this->flags = $flags;
    }

    public function read()
    {
        $this->flags = array();
        while ($this->input) {
            $this->flags[] = ord($this->read_byte());
        }
    }

    public function body()
    {
        $bytes = '';
        foreach ($this->flags as $f) {
            $bytes .= chr($f);
        }
        return $bytes;
    }
}

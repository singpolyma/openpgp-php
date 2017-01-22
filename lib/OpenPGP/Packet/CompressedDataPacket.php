<?php

namespace OpenPGP\Packet;

use OpenPGP\Message\Message;

/**
 * OpenPGP Compressed Data packet (tag 8).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.6
 */
class CompressedDataPacket extends Packet implements \IteratorAggregate, \ArrayAccess
{
    public $algorithm;
    /* see http://tools.ietf.org/html/rfc4880#section-9.3 */
    public static $algorithms = array(0 => 'Uncompressed', 1 => 'ZIP', 2 => 'ZLIB', 3 => 'BZip2');
    public function read()
    {
        $this->algorithm = ord($this->read_byte());
        $this->data = $this->read_bytes($this->length);
        switch ($this->algorithm) {
            case 0:
                $this->data = Message::parse($this->data);
                break;
            case 1:
                $this->data = Message::parse(gzinflate($this->data));
                break;
            case 2:
                $this->data = Message::parse(gzuncompress($this->data));
                break;
            case 3:
                $this->data = Message::parse(bzdecompress($this->data));
                break;
            default:
                /* TODO error? */
        }
    }

    public function body()
    {
        $body = chr($this->algorithm);
        switch ($this->algorithm) {
            case 0:
                $body .= $this->data->to_bytes();
                break;
            case 1:
                $body .= gzdeflate($this->data->to_bytes());
                break;
            case 2:
                $body .= gzcompress($this->data->to_bytes());
                break;
            case 3:
                $body .= bzcompress($this->data->to_bytes());
                break;
            default:
                /* TODO error? */
        }
        return $body;
    }

    // IteratorAggregate interface

    public function getIterator()
    {
        return new \ArrayIterator($this->data->packets);
    }

    // ArrayAccess interface

    public function offsetExists($offset)
    {
        return isset($this->data[$offset]);
    }

    public function offsetGet($offset)
    {
        return $this->data[$offset];
    }

    public function offsetSet($offset, $value)
    {
        return is_null($offset) ? $this->data[] = $value : $this->data[$offset] = $value;
    }

    public function offsetUnset($offset)
    {
        unset($this->data[$offset]);
    }
}

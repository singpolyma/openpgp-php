<?php

namespace OpenPGP\Packet;

/**
 * OpenPGP Literal Data packet (tag 11).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.9
 */
class LiteralDataPacket extends Packet
{
    public $format, $filename, $timestamp;

    function __construct($data=NULL, $opt=array()) {
        parent::__construct();
        $this->data = $data;
        $this->format = isset($opt['format']) ? $opt['format'] : 'b';
        $this->filename = isset($opt['filename']) ? $opt['filename'] : 'data';
        $this->timestamp = isset($opt['timestamp']) ? $opt['timestamp'] : time();
    }

    function normalize($clearsign=false) {
        if($clearsign && ($this->format != 'u' && $this->format != 't')) {
            $this->format = 'u'; // Clearsign must be text
        }

        if($this->format == 'u' || $this->format == 't') { // Normalize line endings
            $this->data = str_replace("\n", "\r\n", str_replace("\r", "\n", str_replace("\r\n", "\n", $this->data)));
        }

        if($clearsign) {
            // When clearsigning, do not sign over trailing whitespace
            $this->data = preg_replace('/\s+\r/', "\r", $this->data);
        }
    }

    function read() {
        $this->size = $this->length - 1 - 4;
        $this->format = $this->read_byte();
        $filename_length = ord($this->read_byte());
        $this->size -= $filename_length;
        $this->filename = $this->read_bytes($filename_length);
        $this->timestamp = $this->read_timestamp();
        $this->data = $this->read_bytes($this->size);
    }

    function body() {
        return $this->format.chr(strlen($this->filename)).$this->filename.pack('N', $this->timestamp).$this->data;
    }
}
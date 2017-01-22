<?php

namespace OpenPGP\Packet;

/**
 * OpenPGP packet.
 *
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-4.3
 */
class Packet
{
    public $tag;
    public $size;
    public $data;
    public $input;
    public $length;

    public static function class_for($tag)
    {
        return isset(self::$tags[$tag]) && class_exists(
            $class = 'OpenPGP_' . self::$tags[$tag] . 'Packet') ? $class : __CLASS__;
    }

    /**
     * Parses an OpenPGP packet.
     *
     * Partial body lengths based on https://github.com/toofishes/python-pgpdump/blob/master/pgpdump/packet.py
     *
     * @see http://tools.ietf.org/html/rfc4880#section-4.2
     */
    public static function parse(&$input)
    {
        $packet = null;
        if (strlen($input) > 0) {
            $parser = ord($input[0]) & 64 ? 'parse_new_format' : 'parse_old_format';

            $header_start0 = 0;
            $consumed = 0;
            $packet_data = "";
            do {
                list($tag, $data_offset, $data_length, $partial) = self::$parser($input, $header_start0);

                $data_start0 = $header_start0 + $data_offset;
                $header_start0 = $data_start0 + $data_length - 1;
                $packet_data .= substr($input, $data_start0, $data_length);

                $consumed += $data_offset + $data_length;
                if ($partial) {
                    $consumed -= 1;
                }
            } while ($partial === true && $parser === 'parse_new_format');

            if ($tag && ($class = self::class_for($tag))) {
                /** @var Packet $packet */
                $packet = new $class();
                $packet->tag    = $tag;
                $packet->input  = $packet_data;
                $packet->length = strlen($packet_data);
                $packet->read();
                unset($packet->input);
                unset($packet->length);
            }
            $input = substr($input, $consumed);
        }
        return $packet;
    }

    /**
     * Parses a new-format (RFC 4880) OpenPGP packet.
     *
     * @see http://tools.ietf.org/html/rfc4880#section-4.2.2
     */
    public static function parse_new_format($input, $header_start = 0)
    {
        $tag = ord($input[0]) & 63;
        $len = ord($input[$header_start + 1]);
        if ($len < 192) { // One octet length
            return array($tag, 2, $len, false);
        }
        if ($len > 191 && $len < 224) { // Two octet length
            return array($tag, 3, (($len - 192) << 8) + ord($input[$header_start + 2]) + 192, false);
        }
        if ($len == 255) { // Five octet length
            $unpacked = unpack('N', substr($input, $header_start + 2, 4));
            return array($tag, 6, reset($unpacked), false);
        }
        // Partial body lengths
        return array($tag, 2, 1 << ($len & 0x1f), true);
    }

    /**
     * Parses an old-format (PGP 2.6.x) OpenPGP packet.
     *
     * @see http://tools.ietf.org/html/rfc4880#section-4.2.1
     */
    public static function parse_old_format($input)
    {
        $len = ($tag = ord($input[0])) & 3;
        $tag = ($tag >> 2) & 15;
        switch ($len) {
            case 0: // The packet has a one-octet length. The header is 2 octets long.
                $head_length = 2;
                $data_length = ord($input[1]);
                break;
            case 1: // The packet has a two-octet length. The header is 3 octets long.
                $head_length = 3;
                $data_length = unpack('n', substr($input, 1, 2));
                $data_length = $data_length[1];
                break;
            case 2: // The packet has a four-octet length. The header is 5 octets long.
                $head_length = 5;
                $data_length = unpack('N', substr($input, 1, 4));
                $data_length = $data_length[1];
                break;
            case 3: // The packet is of indeterminate length. The header is 1 octet long.
                $head_length = 1;
                $data_length = strlen($input) - $head_length;
                break;
        }
        return array($tag, $head_length, $data_length, false);
    }

    public function __construct($data=null)
    {
        $this->tag = array_search(substr(substr(get_class($this), 8), 0, -6), self::$tags);
        $this->data = $data;
    }

    public function read()
    {
    }

    public function body()
    {
        return $this->data; // Will normally be overridden by subclasses
    }

    public function header_and_body()
    {
        $body = $this->body(); // Get body first, we will need it's length
        $tag = chr($this->tag | 0xC0); // First two bits are 1 for new packet format
        $size = chr(255).pack('N', strlen($body)); // Use 5-octet lengths
        return array('header' => $tag.$size, 'body' => $body);
    }

    public function to_bytes()
    {
        $data = $this->header_and_body();
        return $data['header'].$data['body'];
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-3.5
     */
    public function read_timestamp()
    {
        return $this->read_unpacked(4, 'N');
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-3.2
     */
    public function read_mpi()
    {
        $length = $this->read_unpacked(2, 'n');  // length in bits
        $length = (int)floor(($length + 7) / 8); // length in bytes
        return $this->read_bytes($length);
    }

    /**
     * @see http://php.net/manual/en/function.unpack.php
     */
    public function read_unpacked($count, $format)
    {
        $unpacked = unpack($format, $this->read_bytes($count));
        return reset($unpacked);
    }

    public function read_byte()
    {
        return ($bytes = $this->read_bytes()) ? $bytes[0] : null;
    }

    public function read_bytes($count = 1)
    {
        $bytes = substr($this->input, 0, $count);
        $this->input = substr($this->input, $count);
        return $bytes;
    }

    public static $tags = array(
        1 => 'AsymmetricSessionKey',      // Public-Key Encrypted Session Key
        2 => 'Signature',                 // Signature Packet
        3 => 'SymmetricSessionKey',       // Symmetric-Key Encrypted Session Key Packet
        4 => 'OnePassSignature',          // One-Pass Signature Packet
        5 => 'SecretKey',                 // Secret-Key Packet
        6 => 'PublicKey',                 // Public-Key Packet
        7 => 'SecretSubkey',              // Secret-Subkey Packet
        8 => 'CompressedData',            // Compressed Data Packet
        9 => 'EncryptedData',             // Symmetrically Encrypted Data Packet
        10 => 'Marker',                    // Marker Packet
        11 => 'LiteralData',               // Literal Data Packet
        12 => 'Trust',                     // Trust Packet
        13 => 'UserID',                    // User ID Packet
        14 => 'PublicSubkey',              // Public-Subkey Packet
        17 => 'UserAttribute',             // User Attribute Packet
        18 => 'IntegrityProtectedData',    // Sym. Encrypted and Integrity Protected Data Packet
        19 => 'ModificationDetectionCode', // Modification Detection Code Packet
        60 => 'Experimental',              // Private or Experimental Values
        61 => 'Experimental',              // Private or Experimental Values
        62 => 'Experimental',              // Private or Experimental Values
        63 => 'Experimental',              // Private or Experimental Values
    );
}

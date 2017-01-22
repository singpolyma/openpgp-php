<?php
// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP.php is a pure-PHP implementation of the OpenPGP Message Format
 * (RFC 4880).
 *
 * @package OpenPGP
 * @version 0.0.1
 * @author  Arto Bendiken <arto.bendiken@gmail.com>
 * @author  Stephen Paul Weber <singpolyma@singpolyma.net>
 * @see     http://github.com/bendiken/openpgp-php
 */
namespace OpenPGP;

/**
 * @see http://tools.ietf.org/html/rfc4880
 */
class OpenPGP
{
    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     * @see http://tools.ietf.org/html/rfc2045
     */
    static function enarmor($data, $marker = 'MESSAGE', array $headers = array()) {
        $text = self::header($marker) . "\n";
        foreach ($headers as $key => $value) {
            $text .= $key . ': ' . (string)$value . "\n";
        }
        $text .= "\n" . base64_encode($data);
        $text .= "\n".'=' . base64_encode(substr(pack('N', self::crc24($data)), 1)) . "\n";
        $text .= self::footer($marker) . "\n";
        return $text;
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc2045
     */
    static function unarmor($text, $header = 'PGP PUBLIC KEY BLOCK') {
        $header = self::header($header);
        $text = str_replace(array("\r\n", "\r"), array("\n", ''), $text);
        if (($pos1 = strpos($text, $header)) !== FALSE &&
            ($pos1 = strpos($text, "\n\n", $pos1 += strlen($header))) !== FALSE &&
            ($pos2 = strpos($text, "\n=", $pos1 += 2)) !== FALSE) {
            return base64_decode($text = substr($text, $pos1, $pos2 - $pos1));
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     */
    static function header($marker) {
        return '-----BEGIN ' . strtoupper((string)$marker) . '-----';
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     */
    static function footer($marker) {
        return '-----END ' . strtoupper((string)$marker) . '-----';
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc4880#section-6.1
     */
    static function crc24($data) {
        $crc = 0x00b704ce;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= (ord($data[$i]) & 255) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x01000000) {
                    $crc ^= 0x01864cfb;
                }
            }
        }
        return $crc & 0x00ffffff;
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-12.2
     */
    static function bitlength($data) {
        return (strlen($data) - 1) * 8 + (int)floor(log(ord($data[0]), 2)) + 1;
    }

    static function decode_s2k_count($c) {
        return ((int)16 + ($c & 15)) << (($c >> 4) + 6);
    }

    static function encode_s2k_count($iterations) {
        if($iterations >= 65011712) return 255;

        $count = $iterations >> 6;
        $c = 0;
        while($count >= 32) {
            $count = $count >> 1;
            $c++;
        }
        $result = ($c << 4) | ($count - 16);

        if(OpenPGP::decode_s2k_count($result) < $iterations) {
            return $result + 1;
        }

        return $result;
    }
}

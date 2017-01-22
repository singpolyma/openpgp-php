<?php

namespace OpenPGP\Packet\PublicKeyPacket;

use OpenPGP\OpenPGP;
use OpenPGP\Packet\Packet;

/**
 * OpenPGP Public-Key packet (tag 6).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.1
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class PublicKeyPacket extends Packet {
    public $version, $timestamp, $algorithm;
    public $key, $key_id, $fingerprint;
    public $v3_days_of_validity;

    function __construct($key=array(), $algorithm='RSA', $timestamp=NULL, $version=4) {
        parent::__construct();

        if($key instanceof PublicKeyPacket) {
            $this->algorithm = $key->algorithm;
            $this->key = array();

            // Restrict to only the fields we need
            foreach (self::$key_fields[$this->algorithm] as $field) {
                $this->key[$field] = $key->key[$field];
            }

            $this->key_id = $key->key_id;
            $this->fingerprint = $key->fingerprint;
            $this->timestamp = $key->timestamp;
            $this->version = $key->version;
            $this->v3_days_of_validity = $key->v3_days_of_validity;
        } else {
            $this->key = $key;
            if(is_string($this->algorithm = $algorithm)) {
                $this->algorithm = array_search($this->algorithm, self::$algorithms);
            }
            $this->timestamp = $timestamp ? $timestamp : time();
            $this->version = $version;

            if(count($this->key) > 0) {
                $this->key_id = substr($this->fingerprint(), -8);
            }
        }
    }

    // Find self signatures in a message, these often contain metadata about the key
    function self_signatures($message) {
        $sigs = array();
        $keyid16 = strtoupper(substr($this->fingerprint, -16));
        foreach($message as $p) {
            if($p instanceof SignaturePacket) {
                if(strtoupper($p->issuer()) == $keyid16) {
                    $sigs[] = $p;
                } else {
                    foreach(array_merge($p->hashed_subpackets, $p->unhashed_subpackets) as $s) {
                        if($s instanceof OpenPGP_SignaturePacket_EmbeddedSignaturePacket && strtoupper($s->issuer()) == $keyid16) {
                            $sigs[] = $p;
                            break;
                        }
                    }
                }
            } else if(count($sigs)) break; // After we've seen a self sig, the next non-sig stop all self-sigs
        }
        return $sigs;
    }

    // Find expiry time of this key based on the self signatures in a message
    function expires($message) {
        foreach($this->self_signatures($message) as $p) {
            foreach(array_merge($p->hashed_subpackets, $p->unhashed_subpackets) as $s) {
                if($s instanceof OpenPGP_SignaturePacket_KeyExpirationTimePacket) {
                    return $this->timestamp + $s->data;
                }
            }
        }
        return NULL; // Never expires
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
     */
    function read() {
        switch ($this->version = ord($this->read_byte())) {
            case 3:
                $this->timestamp = $this->read_timestamp();
                $this->v3_days_of_validity = $this->read_unpacked(2, 'n');
                $this->algorithm = ord($this->read_byte());
                $this->read_key_material();
                break;
            case 4:
                $this->timestamp = $this->read_timestamp();
                $this->algorithm = ord($this->read_byte());
                $this->read_key_material();
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
     */
    function read_key_material() {
        foreach (self::$key_fields[$this->algorithm] as $field) {
            $this->key[$field] = $this->read_mpi();
        }
        $this->key_id = substr($this->fingerprint(), -8);
    }

    function fingerprint_material() {
        switch ($this->version) {
            case 3:
                $material = array();
                foreach (self::$key_fields[$this->algorithm] as $i) {
                    $material[] = pack('n', OpenPGP::bitlength($this->key[$i]));
                    $material[] = $this->key[$i];
                }
                return $material;
            case 4:
                $head = array(
                    chr(0x99), NULL,
                    chr($this->version), pack('N', $this->timestamp),
                    chr($this->algorithm),
                );
                $material = array();
                foreach (self::$key_fields[$this->algorithm] as $i) {
                    $material[] = pack('n', OpenPGP::bitlength($this->key[$i]));
                    $material[] = $this->key[$i];
                }
                $material = implode('', $material);
                $head[1] = pack('n', 6 + strlen($material));
                $head[] = $material;
                return $head;
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-12.2
     * @see http://tools.ietf.org/html/rfc4880#section-3.3
     */
    function fingerprint() {
        switch ($this->version) {
            case 2:
            case 3:
                return $this->fingerprint = strtoupper(md5(implode('', $this->fingerprint_material())));
            case 4:
                return $this->fingerprint = strtoupper(sha1(implode('', $this->fingerprint_material())));
        }
    }

    function body() {
        switch ($this->version) {
            case 2:
            case 3:
                return implode('', array_merge(array(
                        chr($this->version) . pack('N', $this->timestamp) .
                        pack('n', $this->v3_days_of_validity) . chr($this->algorithm)
                    ), $this->fingerprint_material())
                );
            case 4:
                return implode('', array_slice($this->fingerprint_material(), 2));
        }
    }

    static $key_fields = array(
        1 => array('n', 'e'),           // RSA
        16 => array('p', 'g', 'y'),      // ELG-E
        17 => array('p', 'q', 'g', 'y'), // DSA
    );

    static $algorithms = array(
        1 => 'RSA',
        2 => 'RSA',
        3 => 'RSA',
        16 => 'ELGAMAL',
        17 => 'DSA',
        18 => 'ECC',
        19 => 'ECDSA',
        21 => 'DH'
    );

}

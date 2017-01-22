<?php

namespace OpenPGP\Message;

/**
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-11
 * @see http://tools.ietf.org/html/rfc4880#section-11.3
 */
class Message implements \IteratorAggregate, \ArrayAccess {
    public $uri = NULL;
    public $packets = array();

    static function parse_file($path) {
        if (($msg = self::parse(file_get_contents($path)))) {
            $msg->uri = preg_match('!^[\w\d]+://!', $path) ? $path : 'file://' . realpath($path);
            return $msg;
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-4.1
     * @see http://tools.ietf.org/html/rfc4880#section-4.2
     */
    static function parse($input) {
        if (is_resource($input)) {
            return self::parse_stream($input);
        }
        if (is_string($input)) {
            return self::parse_string($input);
        }
    }

    static function parse_stream($input) {
        return self::parse_string(stream_get_contents($input));
    }

    static function parse_string($input) {
        $msg = new self;
        while (($length = strlen($input)) > 0) {
            if (($packet = Packet::parse($input))) {
                $msg[] = $packet;
            }
            if ($length == strlen($input)) { // is parsing stuck?
                break;
            }
        }
        return $msg;
    }

    function __construct(array $packets = array()) {
        $this->packets = $packets;
    }

    function to_bytes() {
        $bytes = '';
        foreach($this as $p) {
            $bytes .= $p->to_bytes();
        }
        return $bytes;
    }

    /**
     * Extract signed objects from a well-formatted message
     *
     * Recurses into CompressedDataPacket
     *
     * @see http://tools.ietf.org/html/rfc4880#section-11
     */
    function signatures() {
        $msg = $this;
        while($msg[0] instanceof OpenPGP_CompressedDataPacket) $msg = $msg[0]->data;

        $key = NULL;
        $userid = NULL;
        $subkey = NULL;
        $sigs = array();
        $final_sigs = array();

        foreach($msg as $idx => $p) {
            if($p instanceof OpenPGP_LiteralDataPacket) {
                return array(array($p, array_values(array_filter($msg->packets, function($p) {
                    return $p instanceof OpenPGP_SignaturePacket;
                }))));
            } else if($p instanceof OpenPGP_PublicSubkeyPacket || $p instanceof OpenPGP_SecretSubkeyPacket) {
                if($userid) {
                    array_push($final_sigs, array($key, $userid, $sigs));
                    $userid = NULL;
                } else if($subkey) {
                    array_push($final_sigs, array($key, $subkey, $sigs));
                    $key = NULL;
                }
                $sigs = array();
                $subkey = $p;
            } else if($p instanceof OpenPGP_PublicKeyPacket) {
                if($userid) {
                    array_push($final_sigs, array($key, $userid, $sigs));
                    $userid = NULL;
                } else if($subkey) {
                    array_push($final_sigs, array($key, $subkey, $sigs));
                    $subkey = NULL;
                } else if($key) {
                    array_push($final_sigs, array($key, $sigs));
                    $key = NULL;
                }
                $sigs = array();
                $key = $p;
            } else if($p instanceof OpenPGP_UserIDPacket) {
                if($userid) {
                    array_push($final_sigs, array($key, $userid, $sigs));
                    $userid = NULL;
                } else if($key) {
                    array_push($final_sigs, array($key, $sigs));
                }
                $sigs = array();
                $userid = $p;
            } else if($p instanceof OpenPGP_SignaturePacket) {
                $sigs[] = $p;
            }
        }

        if($userid) {
            array_push($final_sigs, array($key, $userid, $sigs));
        } else if($subkey) {
            array_push($final_sigs, array($key, $subkey, $sigs));
        } else if($key) {
            array_push($final_sigs, array($key, $sigs));
        }

        return $final_sigs;
    }

    /**
     * Function to extract verified signatures
     * $verifiers is an array of callbacks formatted like array('RSA' => array('SHA256' => CALLBACK)) that take two parameters: raw message and signature packet
     */
    function verified_signatures($verifiers) {
        $signed = $this->signatures();
        $vsigned = array();

        foreach($signed as $sign) {
            $signatures = array_pop($sign);
            $vsigs = array();

            foreach($signatures as $sig) {
                $verifier = $verifiers[$sig->key_algorithm_name()][$sig->hash_algorithm_name()];
                if($verifier && $this->verify_one($verifier, $sign, $sig)) {
                    $vsigs[] = $sig;
                }
            }
            array_push($sign, $vsigs);
            $vsigned[] = $sign;
        }

        return $vsigned;
    }

    function verify_one($verifier, $sign, $sig) {
        if($sign[0] instanceof OpenPGP_LiteralDataPacket) {
            $sign[0]->normalize();
            $raw = $sign[0]->data;
        } else if(isset($sign[1]) && $sign[1] instanceof OpenPGP_UserIDPacket) {
            $raw = implode('', array_merge($sign[0]->fingerprint_material(), array(chr(0xB4),
                pack('N', strlen($sign[1]->body())), $sign[1]->body())));
        } else if(isset($sign[1]) && ($sign[1] instanceof OpenPGP_PublicSubkeyPacket || $sign[1] instanceof OpenPGP_SecretSubkeyPacket)) {
            $raw = implode('', array_merge($sign[0]->fingerprint_material(), $sign[1]->fingerprint_material()));
        } else if($sign[0] instanceof OpenPGP_PublicKeyPacket) {
            $raw = implode('', $sign[0]->fingerprint_material());
        } else {
            return NULL;
        }
        return call_user_func($verifier, $raw.$sig->trailer, $sig);
    }

    // IteratorAggregate interface

    function getIterator() {
        return new \ArrayIterator($this->packets);
    }

    // ArrayAccess interface

    function offsetExists($offset) {
        return isset($this->packets[$offset]);
    }

    function offsetGet($offset) {
        return $this->packets[$offset];
    }

    function offsetSet($offset, $value) {
        return is_null($offset) ? $this->packets[] = $value : $this->packets[$offset] = $value;
    }

    function offsetUnset($offset) {
        unset($this->packets[$offset]);
    }
}

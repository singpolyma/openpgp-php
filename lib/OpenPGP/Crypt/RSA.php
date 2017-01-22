<?php

namespace OpenPGP\Crypt;

// From http://phpseclib.sourceforge.net/
use OpenPGP\Message\Message;
use OpenPGP\Packet\AsymmetricSessionKeyPacket;
use OpenPGP\Packet\LiteralDataPacket;
use OpenPGP\Packet\PublicKeyPacket\PublicKeyPacket;
use OpenPGP\Packet\PublicKeyPacket\SecretKeyPacket;
use OpenPGP\Packet\SignaturePacket\SignaturePacket;
use OpenPGP\Packet\SignaturePacket\SubPacket\IssuerPacket;
use OpenPGP\Packet\SignaturePacket\SubPacket\KeyFlagsPacket\KeyFlagsPacket;
use phpseclib\Crypt\RSA as Crypt_RSA;
use phpseclib\Math\BigInteger as Math_BigInteger;

define('CRYPT_RSA_ENCRYPTION_PKCS1', Crypt_RSA::ENCRYPTION_PKCS1);
define('CRYPT_RSA_SIGNATURE_PKCS1', Crypt_RSA::SIGNATURE_PKCS1);

// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP_Crypt_RSA.php is a wrapper for using the classes from OpenPGP.php with Crypt_RSA
 *
 * @package OpenPGP
 */
class RSA
{
    protected $key;
    protected $message;

    // Construct a wrapper object from a key or a message packet
    public function __construct($packet)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if ($packet instanceof PublicKeyPacket || $packet[0] instanceof PublicKeyPacket) { // If it's a key (other keys are subclasses of this one)
            $this->key = $packet;
        } else {
            $this->message = $packet;
        }
    }

    public function key($keyid=null)
    {
        if (!$this->key) {
            return null;
        } // No key
        if ($this->key instanceof Message) {
            foreach ($this->key as $p) {
                if ($p instanceof PublicKeyPacket) {
                    if (!$keyid || strtoupper(substr($p->fingerprint, strlen($keyid)*-1)) == strtoupper($keyid)) {
                        return $p;
                    }
                }
            }
        }
        return $this->key;
    }

    // Get Crypt_RSA for the public key
    public function public_key($keyid=null)
    {
        return self::convert_public_key($this->key($keyid));
    }

    // Get Crypt_RSA for the private key
    public function private_key($keyid=null)
    {
        return self::convert_private_key($this->key($keyid));
    }

    // Pass a message to verify with this key, or a key (OpenPGP or Crypt_RSA) to check this message with
    // Second optional parameter to specify which signature to verify (if there is more than one)
    public function verify($packet)
    {
        $self = $this; // For old PHP
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if (!$this->message) {
            $m = $packet;
            $verifier = function ($m, $s) use ($self) {
                $key = $self->public_key($s->issuer());
                if (!$key) {
                    return false;
                }
                $key->setHash(strtolower($s->hash_algorithm_name()));
                return $key->verify($m, reset($s->data));
            };
        } else {
            if (!($packet instanceof Crypt_RSA)) {
                $packet = new self($packet);
            }

            $m = $this->message;
            $verifier = function ($m, $s) use ($self, $packet) {
                if (!($packet instanceof Crypt_RSA)) {
                    $key = $packet->public_key($s->issuer());
                }
                if (!$key) {
                    return false;
                }
                $key->setHash(strtolower($s->hash_algorithm_name()));
                return $key->verify($m, reset($s->data));
            };
        }

        return $m->verified_signatures(array('RSA' => array(
            'MD5'    => $verifier,
            'SHA1'   => $verifier,
            'SHA224' => $verifier,
            'SHA256' => $verifier,
            'SHA384' => $verifier,
            'SHA512' => $verifier
        )));
    }

    // Pass a message to sign with this key, or a secret key to sign this message with
    // Second parameter is hash algorithm to use (default SHA256)
    // Third parameter is the 16-digit key ID to use... defaults to the key id in the key packet
    public function sign($packet, $hash='SHA256', $keyid=null)
    {
        if (!is_object($packet)) {
            if ($this->key) {
                $packet = new LiteralDataPacket($packet);
            } else {
                $packet = Message::parse($packet);
            }
        }

        if ($packet instanceof SecretKeyPacket || $packet instanceof Crypt_RSA
            || ($packet instanceof \ArrayAccess && $packet[0] instanceof SecretKeyPacket)) {
            $key = $packet;
            $message = $this->message;
        } else {
            $key = $this->key;
            $message = $packet;
        }

        if (!$key || !$message) {
            return null;
        } // Missing some data

        if ($message instanceof Message) {
            $sign = $message->signatures();
            $message = $sign[0][0];
        }

        if (!($key instanceof Crypt_RSA)) {
            $key = new self($key);
            if (!$keyid) {
                $keyid = substr($key->key()->fingerprint, -16, 16);
            }
            $key = $key->private_key($keyid);
        }
        $key->setHash(strtolower($hash));

        $sig = new SignaturePacket($message, 'RSA', strtoupper($hash));
        $sig->hashed_subpackets[] = new IssuerPacket($keyid);
        $sig->sign_data(array('RSA' => array($hash => function ($data) use ($key) {
            return array($key->sign($data));
        })));

        return new Message(array($sig, $message));
    }

    /** Pass a message with a key and userid packet to sign */
    // TODO: merge this with the normal sign function
    public function sign_key_userid($packet, $hash='SHA256', $keyid=null)
    {
        if (is_array($packet)) {
            $packet = new Message($packet);
        } elseif (!is_object($packet)) {
            $packet = Message::parse($packet);
        }

        $key = $this->private_key($keyid);
        if (!$key || !$packet) {
            return null;
        } // Missing some data

        if (!$keyid) {
            $keyid = substr($this->key->fingerprint, -16);
        }
        $key->setHash(strtolower($hash));

        $sig = null;
        foreach ($packet as $p) {
            if ($p instanceof SignaturePacket) {
                $sig = $p;
            }
        }
        if (!$sig) {
            $sig = new SignaturePacket($packet, 'RSA', strtoupper($hash));
            $sig->signature_type = 0x13;
            $sig->hashed_subpackets[] = new KeyFlagsPacket(array(0x01 | 0x02));
            $sig->hashed_subpackets[] = new IssuerPacket($keyid);
            $packet[] = $sig;
        }

        $sig->sign_data(array('RSA' => array($hash => function ($data) use ($key) {
            return array($key->sign($data));
        })));

        return $packet;
    }

    public function decrypt($packet)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }

        if ($packet instanceof SecretKeyPacket || $packet instanceof Crypt_RSA
            || ($packet instanceof \ArrayAccess && $packet[0] instanceof SecretKeyPacket)) {
            $keys = $packet;
            $message = $this->message;
        } else {
            $keys = $this->key;
            $message = $packet;
        }

        if (!$keys || !$message) {
            return null;
        } // Missing some data

        if (!($keys instanceof Crypt_RSA)) {
            $keys = new self($keys);
        }

        foreach ($message as $p) {
            if ($p instanceof AsymmetricSessionKeyPacket) {
                if ($keys instanceof Crypt_RSA) {
                    $sk = self::try_decrypt_session($keys, substr($p->encrypted_data, 2));
                } elseif (strlen(str_replace('0', '', $p->keyid)) < 1) {
                    foreach ($keys->key as $k) {
                        $sk = self::try_decrypt_session(self::convert_private_key($k), substr($p->encrypted_data, 2));
                        if ($sk) {
                            break;
                        }
                    }
                } else {
                    $key = $keys->private_key($p->keyid);
                    $sk = self::try_decrypt_session($key, substr($p->encrypted_data, 2));
                }

                if (!$sk) {
                    continue;
                }

                $r = OpenPGP_Crypt_Symmetric::decryptPacket(OpenPGP_Crypt_Symmetric::getEncryptedData($message), $sk[0], $sk[1]);
                if ($r) {
                    return $r;
                }
            }
        }

        return null; /* Failed */
    }

    public static function try_decrypt_session($key, $edata)
    {
        $key->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        $data = $key->decrypt($edata);
        $sk = substr($data, 1, strlen($data)-3);
        $chk = unpack('n', substr($data, -2));
        $chk = reset($chk);

        $sk_chk = 0;
        for ($i = 0; $i < strlen($sk); $i++) {
            $sk_chk = ($sk_chk + ord($sk{$i})) % 65536;
        }

        if ($sk_chk != $chk) {
            return null;
        }
        return array(ord($data{0}), $sk);
    }

    public static function crypt_rsa_key($mod, $exp, $hash='SHA256')
    {
        $rsa = new Crypt_RSA();
        $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        $rsa->setHash(strtolower($hash));
        $rsa->modulus = new Math_BigInteger($mod, 256);
        $rsa->k = strlen($rsa->modulus->toBytes());
        $rsa->exponent = new Math_BigInteger($exp, 256);
        $rsa->setPublicKey();
        return $rsa;
    }

    public static function convert_key($packet, $private=false)
    {
        if (!is_object($packet)) {
            $packet = Message::parse($packet);
        }
        if ($packet instanceof Message) {
            $packet = $packet[0];
        }

        $mod = $packet->key['n'];
        $exp = $packet->key['e'];
        if ($private) {
            $exp = $packet->key['d'];
        }
        if (!$exp) {
            return null;
        } // Packet doesn't have needed data

        $rsa = self::crypt_rsa_key($mod, $exp);

        if ($private) {
            if ($packet->key['p'] && $packet->key['q']) {
                $rsa->primes = array($packet->key['p'], $packet->key['q']);
            }
            if ($packet->key['u']) {
                $rsa->coefficients = array($packet->key['u']);
            }
        }

        return $rsa;
    }

    public static function convert_public_key($packet)
    {
        return self::convert_key($packet, false);
    }

    public static function convert_private_key($packet)
    {
        return self::convert_key($packet, true);
    }
}

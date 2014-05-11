<?php

namespace phpaes;

/**
 * Implements standard AES via Rihndael 128 + CBC + PKCS7 using either
 * mcrypt OR openssl extensions. Perfers openssl for speed.
 *
 * @package phpaes
 */
class AES implements Encryption {

    // Valid block size -- also IV length
    const BLOCK_SIZE = 16;

    // Valid key sizes
    const KEY_128 = 16;
    const KEY_192 = 24;
    const KEY_256 = 32;


    /** @var string */
    private $key;

    /** @var string */
    private $iv;

    /** @var string */
    private $aesmode = '';

    /**
     * @param string $iv
     * @throws \InvalidArgumentException
     */
    public function setIv($iv) {
        if (strlen($iv) != self::BLOCK_SIZE) {
            throw new \InvalidArgumentException("IV length must be ".self::BLOCK_SIZE." bytes");
        }
        $this->iv = $iv;
    }

    /**
     * @param string $key
     * @throws \InvalidArgumentException
     */
    public function setKey($key) {
        if (!in_array(strlen($key), array(self::KEY_128,self::KEY_192,self::KEY_256))) {
            throw new \InvalidArgumentException("Key length must be ".self::KEY_128.", ".self::KEY_192.", or ".self::KEY_256." bytes");
        }
        $this->aesmode = 'aes-'.(8*strlen($key)).'-cbc';
        $this->key = $key;
    }

    /**
     * @throws \LogicException
     * @return string
     */
    public function getIv() {
        if (!isset($this->iv)) {
            throw new \LogicException('The iv is not set, call setIv() prior to usage');
        }
        return $this->iv;
    }

    /**
     * @throws \LogicException
     * @return string
     */
    public function getKey() {
        if (!isset($this->key)) {
            throw new \LogicException('The key is not set, call setKey() prior to usage');
        }
        return $this->key;
    }


    /** @var resource */
    private $mcryptResource = false;

    const ENGINE_MCRYPT  = 1;
    const ENGINE_OPENSSL = 2;

    /** @var int */
    private $engine;

    public function setEngine($engine) {
        if ($engine == self::ENGINE_MCRYPT) {
            // check & initialize
            if (!function_exists('mcrypt_module_open')) {
                throw new \LogicException('mcrypt functions are missing, you may not run in mcrypt mode');
            }
            $this->mcryptResource = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
            $this->engine = $engine;
            return $this;
        }
        elseif ($engine == self::ENGINE_OPENSSL) {
            // check
            if (!function_exists('openssl_encrypt')) {
                throw new \LogicException('openssl functions are missing, you may not run in openssl mode');
            }
            $this->engine = $engine;
            return $this;
        }
        throw new \InvalidArgumentException('mode was not in the approved list of modes');
    }

    function __construct($engine = self::ENGINE_OPENSSL) {
        $this->setEngine(self::ENGINE_OPENSSL);
    }

    /** @inheritdoc */
    public function encrypt($text) {
        if ($this->engine == self::ENGINE_OPENSSL) {
            $cipherText = openssl_encrypt($text, $this->aesmode, $this->getKey(), OPENSSL_RAW_DATA, $this->getIv());
        }
        else {
            $padded_text = $this->pad($text, 16);
            mcrypt_generic_init($this->mcryptResource, $this->getKey(), $this->getIv());
            $cipherText = mcrypt_generic($this->mcryptResource, $padded_text);
            mcrypt_generic_deinit($this->mcryptResource);
        }
        return $cipherText;
    }

    /** @inheritdoc */
    public function decrypt($cipherText) {
        if ($this->engine == self::ENGINE_OPENSSL) {
            $decrypted_text = openssl_decrypt($cipherText, $this->aesmode, $this->getKey(), OPENSSL_RAW_DATA, $this->getIv());
        }
        else {
            mcrypt_generic_init($this->mcryptResource, $this->getKey(), $this->getIv());
            $decrypted_and_padded_text = mdecrypt_generic($this->mcryptResource, $cipherText);
            mcrypt_generic_deinit($this->mcryptResource);
            $decrypted_text = $this->unpad($decrypted_and_padded_text);
        }
        return $decrypted_text;
    }


    /**
     * Add PKCS#7 padding
     *
     * @param string $data
     * @param int $block_size
     * @return string
     */
    public function pad($data, $block_size) {
        $padding = $block_size - (strlen($data) % $block_size);
        $pattern = chr($padding);
        return $data . str_repeat($pattern, $padding);
    }

    /**
     * Remove PKCS#7 padding
     *
     * @param string $data
     * @return string
     */
    public function unpad($data) {
        // find the last character
        $padChar = substr($data, -1);
        // transform it back to the int of how much the string was padded
        $padLength = ord($padChar);
        // return just the text without that many bytes from the end
        return substr($data, 0, -$padLength);
    }

}

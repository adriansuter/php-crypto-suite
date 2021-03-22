<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\Exceptions\CryptoException;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Alerts\InvalidSalt;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\KeyPair;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;

use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;

class KeyFactory
{
    /**
     * @var SaltFactory
     */
    protected $saltFactory;

    /**
     * @param SaltFactory $saltFactory
     */
    public function __construct(SaltFactory $saltFactory)
    {
        $this->saltFactory = $saltFactory;
    }

    /**
     * @return SaltFactory
     */
    public function getSaltFactory(): SaltFactory
    {
        return $this->saltFactory;
    }

    /**
     * @return EncryptionKey
     *
     * @throws CryptoException
     */
    public function generateEncryptionKey(): EncryptionKey
    {
        try {
            return HaliteKeyFactory::generateEncryptionKey();
        } catch (CannotPerformOperation | InvalidKey $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @return AuthenticationKey
     *
     * @throws CryptoException
     */
    public function generateAuthenticationKey(): AuthenticationKey
    {
        try {
            return HaliteKeyFactory::generateAuthenticationKey();
        } catch (CannotPerformOperation | InvalidKey $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @return EncryptionKeyPair
     *
     * @throws CryptoException
     */
    public function generateEncryptionKeyPair(): EncryptionKeyPair
    {
        try {
            return HaliteKeyFactory::generateEncryptionKeyPair();
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @return SignatureKeyPair
     *
     * @throws CryptoException
     */
    public function generateSignatureKeyPair(): SignatureKeyPair
    {
        try {
            return HaliteKeyFactory::generateSignatureKeyPair();
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param Key|KeyPair $key
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function export($key): HiddenString
    {
        try {
            return HaliteKeyFactory::export($key);
        } catch (CannotPerformOperation | InvalidType | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $keyData
     *
     * @return EncryptionKey
     *
     * @throws CryptoException
     */
    public function importEncryptionKey(HiddenString $keyData): EncryptionKey
    {
        try {
            return HaliteKeyFactory::importEncryptionKey($keyData);
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $keyData
     *
     * @return AuthenticationKey
     *
     * @throws CryptoException
     */
    public function importAuthenticationKey(HiddenString $keyData): AuthenticationKey
    {
        try {
            return HaliteKeyFactory::importAuthenticationKey($keyData);
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignaturePublicKey
     *
     * @throws CryptoException
     */
    public function importSignaturePublicKey(HiddenString $keyData): SignaturePublicKey
    {
        try {
            return HaliteKeyFactory::importSignaturePublicKey($keyData);
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignatureSecretKey
     *
     * @throws CryptoException
     */
    public function importSignatureSecretKey(HiddenString $keyData): SignatureSecretKey
    {
        try {
            return HaliteKeyFactory::importSignatureSecretKey($keyData);
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignatureKeyPair
     *
     * @throws CryptoException
     */
    public function importSignatureKeyPair(HiddenString $keyData): SignatureKeyPair
    {
        try {
            return HaliteKeyFactory::importSignatureKeyPair($keyData);
        } catch (InvalidKey | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $password
     * @param string       $salt
     * @param string       $level
     * @param int          $alg
     *
     * @return EncryptionKey
     *
     * @throws CryptoException
     */
    public function deriveEncryptionKey(
        HiddenString $password,
        string $salt,
        string $level = HaliteKeyFactory::INTERACTIVE,
        int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    ): EncryptionKey {
        try {
            return HaliteKeyFactory::deriveEncryptionKey($password, $salt, $level, $alg);
        } catch (InvalidKey | InvalidSalt | InvalidType | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $password
     * @param string       $salt
     * @param string       $level
     * @param int          $alg
     *
     * @return EncryptionKey
     *
     * @throws CryptoException
     */
    public function derivePepperedEncryptionKey(
        HiddenString $password,
        string $salt,
        string $level = HaliteKeyFactory::INTERACTIVE,
        int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    ): EncryptionKey {
        return $this->deriveEncryptionKey(
            $password,
            $this->saltFactory->derivePepperSalt($salt),
            $level,
            $alg
        );
    }
}

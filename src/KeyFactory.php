<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite;

use ParagonIE\Halite\Alerts\HaliteAlert;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\KeyPair;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;

final class KeyFactory
{
    /**
     * @var SaltFactory
     */
    private $saltFactory;

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
     * @throws HaliteAlert
     */
    public function generateEncryptionKey(): EncryptionKey
    {
        return HaliteKeyFactory::generateEncryptionKey();
    }

    /**
     * @return EncryptionKeyPair
     *
     * @throws HaliteAlert
     */
    public function generateEncryptionKeyPair(): EncryptionKeyPair
    {
        return HaliteKeyFactory::generateEncryptionKeyPair();
    }

    /**
     * @return SignatureKeyPair
     *
     * @throws HaliteAlert
     */
    public function generateSignatureKeyPair(): SignatureKeyPair
    {
        return HaliteKeyFactory::generateSignatureKeyPair();
    }

    /**
     * @param Key|KeyPair $key
     *
     * @return HiddenString
     *
     * @throws HaliteAlert
     */
    public function export($key): HiddenString
    {
        return HaliteKeyFactory::export($key);
    }

    /**
     * @param HiddenString $keyData
     *
     * @return EncryptionKey
     *
     * @throws InvalidKey
     */
    public function importEncryptionKey(HiddenString $keyData): EncryptionKey
    {
        return HaliteKeyFactory::importEncryptionKey($keyData);
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignaturePublicKey
     *
     * @throws InvalidKey
     */
    public function importSignaturePublicKey(HiddenString $keyData): SignaturePublicKey
    {
        return HaliteKeyFactory::importSignaturePublicKey($keyData);
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignatureSecretKey
     *
     * @throws InvalidKey
     */
    public function importSignatureSecretKey(HiddenString $keyData): SignatureSecretKey
    {
        return HaliteKeyFactory::importSignatureSecretKey($keyData);
    }

    /**
     * @param HiddenString $keyData
     *
     * @return SignatureKeyPair
     *
     * @throws InvalidKey
     */
    public function importSignatureKeyPair(HiddenString $keyData): SignatureKeyPair
    {
        return HaliteKeyFactory::importSignatureKeyPair($keyData);
    }

    /**
     * @param HiddenString $password
     * @param string       $salt
     * @param string       $level
     * @param int          $alg
     *
     * @return EncryptionKey
     *
     * @throws HaliteAlert
     */
    public function deriveEncryptionKey(
        HiddenString $password,
        string $salt,
        string $level = HaliteKeyFactory::INTERACTIVE,
        int $alg = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    ): EncryptionKey {
        return HaliteKeyFactory::deriveEncryptionKey($password, $salt, $level, $alg);
    }

    /**
     * @param HiddenString $password
     * @param string       $salt
     * @param string       $level
     * @param int          $alg
     *
     * @return EncryptionKey
     *
     * @throws HaliteAlert
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

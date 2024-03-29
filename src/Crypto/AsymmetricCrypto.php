<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\Exceptions\CryptoException;
use ParagonIE\Halite\Alerts\HaliteAlertInterface;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\PublicKey;
use ParagonIE\Halite\Asymmetric\SecretKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\Halite;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;

class AsymmetricCrypto extends AbstractCrypto
{
    /**
     * @param HiddenString $plaintext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function encrypt(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        try {
            return Crypto::encrypt($plaintext, $ourPrivateKey, $theirPublicKey, $encoding);
        } catch (HaliteAlertInterface | SodiumException  $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $plaintext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param int $size
     * @param string $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function encryptFixedSize(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        int $size,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return $this->encrypt(
            $this->hiddenStringUtilities->pad($plaintext, $size),
            $ourPrivateKey,
            $theirPublicKey,
            $encoding
        );
    }

    /**
     * @param HiddenString $message
     * @param SignatureSecretKey $secretKey
     * @param PublicKey $recipientPublicKey
     * @param string $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function signAndEncrypt(
        HiddenString $message,
        SignatureSecretKey $secretKey,
        PublicKey $recipientPublicKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        try {
            return Crypto::signAndEncrypt($message, $secretKey, $recipientPublicKey, $encoding);
        } catch (HaliteAlertInterface | SodiumException  $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString $message
     * @param SignatureSecretKey $secretKey
     * @param PublicKey $recipientPublicKey
     * @param int $size
     * @param string $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function signAndEncryptFixedSize(
        HiddenString $message,
        SignatureSecretKey $secretKey,
        PublicKey $recipientPublicKey,
        int $size,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return $this->signAndEncrypt(
            $this->hiddenStringUtilities->pad($message, $size),
            $secretKey,
            $recipientPublicKey,
            $encoding
        );
    }

    /**
     * @param string $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function decrypt(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        try {
            return Crypto::decrypt($ciphertext, $ourPrivateKey, $theirPublicKey, $encoding);
        } catch (HaliteAlertInterface | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param string $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function decryptFixedSize(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return $this->hiddenStringUtilities->trim(
            $this->decrypt($ciphertext, $ourPrivateKey, $theirPublicKey, $encoding)
        );
    }

    /**
     * @param string $ciphertext
     * @param SignaturePublicKey $senderPublicKey
     * @param SecretKey $givenSecretKey
     * @param string $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function verifyAndDecrypt(
        string $ciphertext,
        SignaturePublicKey $senderPublicKey,
        SecretKey $givenSecretKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        try {
            return Crypto::verifyAndDecrypt(
                $ciphertext,
                $senderPublicKey,
                $givenSecretKey,
                $encoding
            );
        } catch (HaliteAlertInterface | SodiumException  $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param string $ciphertext
     * @param SignaturePublicKey $senderPublicKey
     * @param SecretKey $givenSecretKey
     * @param string $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function verifyAndDecryptFixedSize(
        string $ciphertext,
        SignaturePublicKey $senderPublicKey,
        SecretKey $givenSecretKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return $this->hiddenStringUtilities->trim(
            $this->verifyAndDecrypt($ciphertext, $senderPublicKey, $givenSecretKey, $encoding)
        );
    }
}

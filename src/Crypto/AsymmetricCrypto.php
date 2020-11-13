<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Crypto;

use ParagonIE\Halite\Alerts\HaliteAlert;
use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\PublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\Halite\Halite;
use ParagonIE\HiddenString\HiddenString;

final class AsymmetricCrypto extends AbstractCrypto
{
    /**
     * @param HiddenString        $plaintext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string              $encoding
     *
     * @return string
     *
     * @throws HaliteAlert
     */
    public function encrypt(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return Crypto::encrypt($plaintext, $ourPrivateKey, $theirPublicKey, $encoding);
    }

    /**
     * @param HiddenString        $plaintext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param int                 $size
     * @param string              $encoding
     *
     * @return string
     *
     * @throws HaliteAlert
     */
    public function encryptFixedSize(
        HiddenString $plaintext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        int $size,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return self::encrypt(
            $this->hiddenStringUtilities->pad($plaintext, $size),
            $ourPrivateKey,
            $theirPublicKey,
            $encoding
        );
    }

    /**
     * @param HiddenString       $message
     * @param SignatureSecretKey $secretKey
     * @param PublicKey          $recipientPublicKey
     * @param string             $encoding
     *
     * @return string
     * @throws HaliteAlert
     */
    public function signAndEncrypt(
        HiddenString $message,
        SignatureSecretKey $secretKey,
        PublicKey $recipientPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return Crypto::signAndEncrypt($message, $secretKey, $recipientPublicKey, $encoding);
    }

    /**
     * @param string              $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string              $encoding
     *
     * @return HiddenString
     *
     * @throws HaliteAlert
     */
    public function decrypt(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return Crypto::decrypt($ciphertext, $ourPrivateKey, $theirPublicKey, $encoding);
    }

    /**
     * @param string              $ciphertext
     * @param EncryptionSecretKey $ourPrivateKey
     * @param EncryptionPublicKey $theirPublicKey
     * @param string              $encoding
     *
     * @return HiddenString
     *
     * @throws HaliteAlert
     */
    public function decryptFixedSize(
        string $ciphertext,
        EncryptionSecretKey $ourPrivateKey,
        EncryptionPublicKey $theirPublicKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return $this->hiddenStringUtilities->trim(
            self::decrypt($ciphertext, $ourPrivateKey, $theirPublicKey, $encoding)
        );
    }
}

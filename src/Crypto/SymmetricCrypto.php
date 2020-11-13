<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Crypto;

use InvalidArgumentException;
use ParagonIE\Halite\Alerts\HaliteAlert;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

final class SymmetricCrypto extends AbstractCrypto
{
    /**
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param string $encoding
     * @return string
     *
     * @throws HaliteAlert
     */
    public function encrypt(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        return Crypto::encrypt($plaintext, $secretKey, $encoding);
    }

    /**
     * @param HiddenString $plaintext
     * @param EncryptionKey $secretKey
     * @param int $size
     * @param string $encoding
     * @return string
     *
     * @throws HaliteAlert
     * @throws InvalidArgumentException
     */
    public function encryptFixedSize(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        int $size,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string
    {
        return self::encrypt(
            $this->hiddenStringUtilities->pad($plaintext, $size),
            $secretKey,
            $encoding
        );
    }

    /**
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param string $encoding
     * @return HiddenString
     *
     * @throws HaliteAlert
     */
    public function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString
    {
        return Crypto::decrypt($ciphertext, $secretKey, $encoding);
    }

    /**
     * @param string $ciphertext
     * @param EncryptionKey $secretKey
     * @param string $encoding
     * @return HiddenString
     *
     * @throws HaliteAlert
     */
    public function decryptFixedSize(
        string $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString
    {
        return $this->hiddenStringUtilities->trim(
            self::decrypt($ciphertext, $secretKey, $encoding)
        );
    }
}

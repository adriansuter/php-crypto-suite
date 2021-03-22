<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\Exceptions\CryptoException;
use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\InvalidDigestLength;
use ParagonIE\Halite\Alerts\InvalidMessage;
use ParagonIE\Halite\Alerts\InvalidSignature;
use ParagonIE\Halite\Alerts\InvalidType;
use ParagonIE\Halite\Halite;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\Config as SymmetricConfig;
use ParagonIE\Halite\Symmetric\Crypto;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use SodiumException;

class SymmetricCrypto extends AbstractCrypto
{
    /**
     * @param string            $message           The message to authenticate (usually this message is encrypted).
     * @param AuthenticationKey $authenticationKey The authentication key.
     * @param string            $encoding          The encoding.
     *
     * @return string The MAC.
     *
     * @throws CryptoException
     */
    public function authenticate(
        string $message,
        AuthenticationKey $authenticationKey,
        string $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        try {
            return Crypto::authenticate($message, $authenticationKey, $encoding);
        } catch (InvalidMessage | InvalidType | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param string               $message
     * @param AuthenticationKey    $authenticationKey
     * @param string               $mac
     * @param string               $encoding
     * @param SymmetricConfig|null $config
     *
     * @return bool
     *
     * @throws CryptoException
     */
    public function verify(
        string $message,
        AuthenticationKey $authenticationKey,
        string $mac,
        string $encoding = Halite::ENCODE_BASE64URLSAFE,
        ?SymmetricConfig $config = null
    ): bool {
        try {
            return Crypto::verify($message, $authenticationKey, $mac, $encoding, $config);
        } catch (InvalidMessage | InvalidSignature | InvalidType | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString  $plaintext
     * @param EncryptionKey $secretKey
     * @param string        $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function encrypt(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        try {
            return Crypto::encrypt($plaintext, $secretKey, $encoding);
        } catch (CannotPerformOperation | InvalidDigestLength | InvalidMessage | InvalidType | SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param HiddenString  $plaintext
     * @param EncryptionKey $secretKey
     * @param int           $size
     * @param string        $encoding
     *
     * @return string
     *
     * @throws CryptoException
     */
    public function encryptFixedSize(
        HiddenString $plaintext,
        EncryptionKey $secretKey,
        int $size,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): string {
        return self::encrypt(
            $this->hiddenStringUtilities->pad($plaintext, $size),
            $secretKey,
            $encoding
        );
    }

    /**
     * @param string        $ciphertext
     * @param EncryptionKey $secretKey
     * @param string        $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function decrypt(
        string $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        try {
            return Crypto::decrypt($ciphertext, $secretKey, $encoding);
        } catch (CannotPerformOperation | InvalidDigestLength | InvalidMessage | InvalidSignature | InvalidType $e) {
            throw new CryptoException($e);
        } catch (SodiumException $e) {
            throw new CryptoException($e);
        }
    }

    /**
     * @param string        $ciphertext
     * @param EncryptionKey $secretKey
     * @param string        $encoding
     *
     * @return HiddenString
     *
     * @throws CryptoException
     */
    public function decryptFixedSize(
        string $ciphertext,
        EncryptionKey $secretKey,
        $encoding = Halite::ENCODE_BASE64URLSAFE
    ): HiddenString {
        return $this->hiddenStringUtilities->trim(
            self::decrypt($ciphertext, $secretKey, $encoding)
        );
    }
}

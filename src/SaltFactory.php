<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite;

use Exception;

use function hash_pbkdf2;
use function random_bytes;

use const SODIUM_CRYPTO_PWHASH_SALTBYTES;

class SaltFactory
{
    /**
     * @var string
     */
    protected string $pepper;

    /**
     * @var int
     */
    protected int $hashIterations;

    /**
     * @var string
     */
    protected string $hashAlgorithm;

    /**
     * @param string $pepper
     * @param int $hashIterations
     * @param string $hashAlgorithm
     */
    public function __construct(string $pepper, int $hashIterations, string $hashAlgorithm = 'sha256')
    {
        $this->pepper = $pepper;
        $this->hashIterations = $hashIterations;
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Generates a new salt.
     *
     * @return string The salt (16 bytes).
     *
     * @throws Exception
     */
    public function generateSalt(): string
    {
        return random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }

    /**
     * Generates a new pepper salt.
     *
     * @return string The pepper salt (16 bytes).
     *
     * @throws Exception
     */
    public function generatePepperSalt(): string
    {
        return $this->derivePepperSalt(
            $this->generateSalt()
        );
    }

    /**
     * Derives a pepper salt given a salt.
     *
     * @param string $salt The salt.
     *
     * @return string The pepper salt (16 bytes).
     */
    public function derivePepperSalt(string $salt): string
    {
        return hash_pbkdf2(
            $this->hashAlgorithm,
            $this->pepper,
            $salt,
            $this->hashIterations,
            SODIUM_CRYPTO_PWHASH_SALTBYTES
        );
    }
}

<?php

/** @noinspection PhpUnhandledExceptionInspection */

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use PHPStan\Testing\TestCase;

use function random_bytes;

use const SODIUM_CRYPTO_PWHASH_SALTBYTES;

class KeyFactoryTest extends TestCase
{
    private function buildKeyFactory(): KeyFactory
    {
        $saltFactory = new SaltFactory(random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES), 99);
        return new KeyFactory($saltFactory);
    }

    public function testGetSaltFactory(): void
    {
        $saltFactory = new SaltFactory(random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES), 99);
        $keyFactory = new KeyFactory($saltFactory);
        $this->assertEquals($saltFactory, $keyFactory->getSaltFactory());
    }

    public function testGenerateEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $this->assertInstanceOf(EncryptionKey::class, $keyFactory->generateEncryptionKey());
    }
}

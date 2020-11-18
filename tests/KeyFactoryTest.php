<?php

/** @noinspection PhpUnhandledExceptionInspection */

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use PHPStan\Testing\TestCase;

use function base64_decode;
use function random_bytes;

use const SODIUM_CRYPTO_PWHASH_SALTBYTES;

class KeyFactoryTest extends TestCase
{
    private function buildKeyFactory(): KeyFactory
    {
        $pepper = base64_decode('aW8/6a+Pld62aD24RnATJA==');
        $saltFactory = new SaltFactory($pepper, 99);
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

    public function testGenerateEncryptionKeyPair(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $this->assertInstanceOf(EncryptionKeyPair::class, $keyFactory->generateEncryptionKeyPair());
    }

    public function testGenerateSignatureKeyPair(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $this->assertInstanceOf(SignatureKeyPair::class, $keyFactory->generateSignatureKeyPair());
    }

    public function testExport(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5184018cdbd068d3d7ec651c7baa2f'
            . '23590e2ad4bbd1f4d2823ccb05a3de370290f4973b066fb8b357b9c6ac8a06e32fe93f0afe3e794754c87673906a55e7baf'
        );

        $key = $keyFactory->importEncryptionKey($keyData);
        $this->assertTrue($keyFactory->export($key)->equals($keyData));
    }

    public function testImportEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5184018cdbd068d3d7ec651c7baa2f'
            . '23590e2ad4bbd1f4d2823ccb05a3de370290f4973b066fb8b357b9c6ac8a06e32fe93f0afe3e794754c87673906a55e7baf'
        );

        $key = $keyFactory->importEncryptionKey($keyData);
        $this->assertTrue($key->isEncryptionKey());
    }

    public function testImportSignaturePublicKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400be176b10ad1e6c7e473d0abdd983f627e89750e4255738ed943d708bc587e6be37529ed7fc613637d40a86b6da5f6'
            . '975d78d1209073af88d38ab59d06803bbdea4eb8df4128c7a89357fd718762ca8ecbbf297f18bb3eb6290ec0c8b74d51886'
        );

        $key = $keyFactory->importSignaturePublicKey($keyData);
        $this->assertTrue($key->isPublicKey());
        $this->assertTrue($key->isSigningKey());
    }

    public function testImportSignatureSecretKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400ada10ffd64374f00340bd3a670692add6d4ae632d2dbef9cf4c037360bc42321f91205ddef8a07cc4'
            . '287441051cbd5633de814a1d5df1f56cb5772ec8d2e58299ad9d8256a869885f7ca884502e81ee9cb81fc08'
            . '7236303e67cd9483ddabf79f69ef9cf94f8e53025964e8879202bd524f94cf30c2792bc2dab62d63991912c2'
        );

        $key = $keyFactory->importSignatureSecretKey($keyData);
        $this->assertTrue($key->isSecretKey());
        $this->assertTrue($key->isSigningKey());
    }

    public function testImportSignatureKeyPair(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '314004007f0d672c628db29836491f1027adfba220a9068c507536b0c18fdc41ed'
            . 'cee8434070d88f3d0d0007067021a653e56f0f751a357df25d9e2c63a7d2ed4ddade6d73d2c410adf9f73770'
            . '01014db61fbdb0b040b3a3bebe481f0c064f2a4d73e528dce2a64322ad48305212547b19341c9239ca913f7e'
            . 'e6dd91b8d972e75bc54a02'
        );

        $key = $keyFactory->importSignatureKeyPair($keyData);
        $this->assertInstanceOf(SignatureKeyPair::class, $key);
    }

    public function testDeriveEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $salt = base64_decode('ERbWegDt+fCUzcO7YEMq2Q==');

        $encryptionKey = $keyFactory->deriveEncryptionKey(new HiddenString('foo'), $salt);
        $this->assertEquals(
            '31400400a72e95a39a7cd45cec82e6848edd1ce467aad3447b7e4bf51bc24ecfad2b34e5bedcb352b77a0c065e'
            . '4110d91d9e48f7462ff2e3632aa8d47214c3ad606722dfd963cb5c683a7aa0e26344ddf22e6559e11e82973ff00c37b2d'
            . '1ee0e7282a5f6',
            $keyFactory->export($encryptionKey)->getString()
        );
    }

    public function testDerivePepperedEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $salt = base64_decode('ERbWegDt+fCUzcO7YEMq2Q==');

        $encryptionKey = $keyFactory->derivePepperedEncryptionKey(new HiddenString('foo'), $salt);
        $this->assertEquals(
            '314004008298e78d2ad2376a93fe42cb1e8853b085bdf3e5a24a990d07b09fd6b3c7eaf9f6832617d69c63329ba5792a'
            . '417e54f8523ede0ef6b596ea46c7ae8d9d0249d0b43bad7ab478de700ced226283e8b7c436eebd9a3b7698dd9c5e76'
            . '96a792229c',
            $keyFactory->export($encryptionKey)->getString()
        );
    }
}

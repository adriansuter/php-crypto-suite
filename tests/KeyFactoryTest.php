<?php

/** @noinspection PhpUnhandledExceptionInspection */

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\EncryptionKeyPair;
use ParagonIE\Halite\KeyFactory as HaliteKeyFactory;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

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

    public function testGenerateAuthenticationKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $this->assertInstanceOf(AuthenticationKey::class, $keyFactory->generateAuthenticationKey());
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
            '31400400'
            . 'b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5'
            . '184018cdbd068d3d7ec651c7baa2f23590e2ad4bbd1f4d2823ccb05a3de37029'
            . '0f4973b066fb8b357b9c6ac8a06e32fe93f0afe3e794754c87673906a55e7baf'
        );

        $key = $keyFactory->importEncryptionKey($keyData);
        $this->assertMatchesRegularExpression(
            '@^3140\d{4}b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5[0-9a-f]{128}$@i',
            $keyFactory->export($key)->getString()
        );
    }

    public function testImportEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400'
            . 'b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5'
            . '184018cdbd068d3d7ec651c7baa2f23590e2ad4bbd1f4d2823ccb05a3de37029'
            . '0f4973b066fb8b357b9c6ac8a06e32fe93f0afe3e794754c87673906a55e7baf'
        );

        $key = $keyFactory->importEncryptionKey($keyData);
        $this->assertTrue($key->isEncryptionKey());
    }

    public function testImportSignaturePublicKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400'
            . 'be176b10ad1e6c7e473d0abdd983f627e89750e4255738ed943d708bc587e6be'
            . '37529ed7fc613637d40a86b6da5f6975d78d1209073af88d38ab59d06803bbde'
            . 'a4eb8df4128c7a89357fd718762ca8ecbbf297f18bb3eb6290ec0c8b74d51886'
        );

        $key = $keyFactory->importSignaturePublicKey($keyData);
        $this->assertTrue($key->isPublicKey());
        $this->assertTrue($key->isSigningKey());
    }

    public function testImportSignatureSecretKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400'
            . 'ada10ffd64374f00340bd3a670692add6d4ae632d2dbef9cf4c037360bc42321'
            . 'f91205ddef8a07cc4287441051cbd5633de814a1d5df1f56cb5772ec8d2e5829'
            . '9ad9d8256a869885f7ca884502e81ee9cb81fc087236303e67cd9483ddabf79f'
            . '69ef9cf94f8e53025964e8879202bd524f94cf30c2792bc2dab62d63991912c2'
        );

        $key = $keyFactory->importSignatureSecretKey($keyData);
        $this->assertTrue($key->isSecretKey());
        $this->assertTrue($key->isSigningKey());
    }

    public function testImportSignatureKeyPair(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $keyData = new HiddenString(
            '31400400'
            . '7f0d672c628db29836491f1027adfba220a9068c507536b0c18fdc41edcee843'
            . '4070d88f3d0d0007067021a653e56f0f751a357df25d9e2c63a7d2ed4ddade6d'
            . '73d2c410adf9f7377001014db61fbdb0b040b3a3bebe481f0c064f2a4d73e528'
            . 'dce2a64322ad48305212547b19341c9239ca913f7ee6dd91b8d972e75bc54a02'
        );

        $key = $keyFactory->importSignatureKeyPair($keyData);
        $this->assertInstanceOf(SignatureKeyPair::class, $key);
    }

    public function testDeriveEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $salt = base64_decode('ERbWegDt+fCUzcO7YEMq2Q==');

        $encryptionKey = $keyFactory->deriveEncryptionKey(new HiddenString('foo'), $salt);
        $expectedEncryptionKey = HaliteKeyFactory::importEncryptionKey(
            new HiddenString(
                '31400400'
                . 'a72e95a39a7cd45cec82e6848edd1ce467aad3447b7e4bf51bc24ecfad2b34e5'
                . 'bedcb352b77a0c065e4110d91d9e48f7462ff2e3632aa8d47214c3ad606722df'
                . 'd963cb5c683a7aa0e26344ddf22e6559e11e82973ff00c37b2d1ee0e7282a5f6'
            )
        );
        $this->assertEquals($expectedEncryptionKey, $encryptionKey);

        $expectedEncryptionKeyV5 = HaliteKeyFactory::importEncryptionKey(
            new HiddenString(
                '31400500'
                . 'a72e95a39a7cd45cec82e6848edd1ce467aad3447b7e4bf51bc24ecfad2b34e5'
                . '4d29cc0602ef50637716ac84b6ae86266f2bc00f5036d91a079b2e2117c128b9'
                . '7d5a2e0d7fd3fe8745fc106da44ae175c190fe230c1dc688f85fd351091123b1'
            )
        );
        $this->assertEquals($expectedEncryptionKeyV5, $encryptionKey);
    }

    public function testDerivePepperedEncryptionKey(): void
    {
        $keyFactory = $this->buildKeyFactory();
        $salt = base64_decode('ERbWegDt+fCUzcO7YEMq2Q==');

        $encryptionKey = $keyFactory->derivePepperedEncryptionKey(new HiddenString('foo'), $salt);
        $expectedEncryptionKey = HaliteKeyFactory::importEncryptionKey(
            new HiddenString(
                '31400400'
                . '8298e78d2ad2376a93fe42cb1e8853b085bdf3e5a24a990d07b09fd6b3c7eaf9'
                . 'f6832617d69c63329ba5792a417e54f8523ede0ef6b596ea46c7ae8d9d0249d0'
                . 'b43bad7ab478de700ced226283e8b7c436eebd9a3b7698dd9c5e7696a792229c'
            )
        );
        $this->assertEquals($expectedEncryptionKey, $encryptionKey);

        $expectedEncryptionKeyV5 = HaliteKeyFactory::importEncryptionKey(
            new HiddenString(
                '31400500'
                . '8298e78d2ad2376a93fe42cb1e8853b085bdf3e5a24a990d07b09fd6b3c7eaf9'
                . '21e9c8d10d79bfe34a7a122ac37b7582ab7e1ba3addec7e43095607e59895f06'
                . '6dfcf98ba3f7de97e36beab0f4cf4264c6b5792d72fb59b4952b1717f2f0944a'
            )
        );
        $this->assertEquals($expectedEncryptionKeyV5, $encryptionKey);
    }
}

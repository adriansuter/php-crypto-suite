<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\Crypto\SymmetricCrypto;
use AdrianSuter\CryptoSuite\HiddenStringUtilities;
use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

class SymmetricCryptoTest extends TestCase
{
    protected function getAuthenticationKey(): AuthenticationKey
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importAuthenticationKey(
            new HiddenString(
                '31400400'
                . '717c2efc7e43805a6a5591968105ec090e4f7bfd6abcddd44bf3396060a19fb8'
                . 'b20d7d03f2a3444cca9abd2c7baa7e6fde2b20b5862cd751f33026ea0b309ef7'
                . 'b7f0511f5519b7f4360ee585dd5daf308e45ef2c6a1de2eca115d7f5c5d7ec22'
            )
        );
    }

    protected function getEncryptionKey(): EncryptionKey
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importEncryptionKey(
            new HiddenString(
                '31400400'
                . 'b86bf3d05faa733380830766a270cbb7665db803883283471b1ac285e8976ef5'
                . '184018cdbd068d3d7ec651c7baa2f23590e2ad4bbd1f4d2823ccb05a3de37029'
                . '0f4973b066fb8b357b9c6ac8a06e32fe93f0afe3e794754c87673906a55e7baf'
            )
        );
    }

    public function testAuthenticate(): void
    {
        $authenticationKey = $this->getAuthenticationKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $this->assertEquals(
            'HFCmJh0WXZN7j8QHM3IRDWQh2T4Fjm8jp1ns7MGnpYjuMSk0X5yCJTiJqNMXy-lhp3kcRIS1PUH-7rklkxU0Aw==',
            $symmetricCrypto->authenticate('test', $authenticationKey)
        );
    }

    public function testVerify(): void
    {
        $authenticationKey = $this->getAuthenticationKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $this->assertTrue(
            $symmetricCrypto->verify(
                'test',
                $authenticationKey,
                'HFCmJh0WXZN7j8QHM3IRDWQh2T4Fjm8jp1ns7MGnpYjuMSk0X5yCJTiJqNMXy-lhp3kcRIS1PUH-7rklkxU0Aw=='
            )
        );
    }

    public function testEncrypt(): void
    {
        $plaintext = new HiddenString('hello');
        $secretKey = $this->getEncryptionKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $symmetricCrypto->encrypt($plaintext, $secretKey);

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(172, strlen($ciphertext));
    }

    public function testEncryptFixedSize(): void
    {
        $plaintext = new HiddenString('hello');
        $secretKey = $this->getEncryptionKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $symmetricCrypto->encryptFixedSize($plaintext, $secretKey, 10);

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(180, strlen($ciphertext));
    }

    public function testDecrypt(): void
    {
        $ciphertext = 'MUIFAMMs222dens6DTodh9Gaih6qaYxKQ0SmFnMLU2Htpc7MgjDF5uUo9p7Nx2KpSHXU3V_x_5f_eYMbID'
            . 'h5JdzdSBQUNeDTMl5iA4kVM0KlyhNdGonJ5_fscpHa-XUvmZ5KmgKWm11SRxJWCjxbnvluRsF6JsP1qsarjoPz6oeG';
        $secretKey = $this->getEncryptionKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $symmetricCrypto->decrypt($ciphertext, $secretKey);

        $this->assertTrue($plaintext->equals(new HiddenString('hello')));
    }

    public function testDecryptFixedSize(): void
    {
        $ciphertext = 'MUIFAEOMWrziULA_XqVW97_dFopbr8jrCOx39A5q3ugZ5cga5osE_5FkPk4JxvlqCrQUbD3dwDLtYluMrFIHgj'
            . 'gja2eDcCAyhqiPrqS2LzNheI58Cfc8cD_KiSgw9v69Bgn4vpTfumKeadJ5_RsinKhWHtyI3bD-ccTr78LVJ2oDhxOplxWy';
        $secretKey = $this->getEncryptionKey();

        $symmetricCrypto = new SymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $symmetricCrypto->decryptFixedSize($ciphertext, $secretKey);

        $this->assertTrue($plaintext->equals(new HiddenString('hello')));
    }
}

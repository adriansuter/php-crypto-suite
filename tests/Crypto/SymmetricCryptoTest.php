<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\Crypto\SymmetricCrypto;
use AdrianSuter\CryptoSuite\HiddenStringUtilities;
use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\Symmetric\AuthenticationKey;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

class SymmetricCryptoTest extends TestCase
{
    protected function getAuthenticationKey(): AuthenticationKey
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importAuthenticationKey(new HiddenString(
            '31400400717c2efc7e43805a6a5591968105ec090e4f7bfd6abcddd44bf3396060a19fb8b20d7d03f2a3444cca9abd2c7baa' .
            '7e6fde2b20b5862cd751f33026ea0b309ef7b7f0511f5519b7f4360ee585dd5daf308e45ef2c6a1de2eca115d7f5c5d7ec22'
        ));
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
}

<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\Crypto\AsymmetricCrypto;
use AdrianSuter\CryptoSuite\Exceptions\CryptoException;
use AdrianSuter\CryptoSuite\HiddenStringUtilities;
use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\Halite\SignatureKeyPair;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

class AsymmetricCryptoTest extends TestCase
{
    protected function getOurKeyPair(): SignatureKeyPair
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importSignatureKeyPair(
            new HiddenString(
                '31400500'
                . 'b633cf5ced0e6e4a54537137a642499fa2a7f89936ac53561f36653ecc12e07a'
                . '2115ed12e4019611449f8645aaeb073412a39491ab16d5cf35152570c5fe16ac'
                . '932b3de533f3c94705e363e9c342fa9e8a77db2816895b0b06d89839143b5011'
                . '428b553ecb18c43d0fd42e14946aa23349720256787fbd11356bb723ce84d8ee'
            )
        );
    }

    protected function getTheirKeyPair(): SignatureKeyPair
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importSignatureKeyPair(
            new HiddenString(
                '31400500'
                . 'f7cdf304b8f22d04a452b0fb0501922392267cc442e0cd508684491f2f6f6f09'
                . 'a09ce0b4596e7053a02bf7de8ca2a5120c6b2a2f469294b64f17d9698afc6741'
                . '89b13e498a01f64493408ff517feb8fa3292ced5fae1f95070f7782604ca93b6'
                . 'db1c868a436460add0d729e6370b98236840f30dfd94eaf0b8da95fbc09dcf7f'
            )
        );
    }

    protected function getOtherKeyPair(): SignatureKeyPair
    {
        $kf = new KeyFactory($this->createMock(SaltFactory::class));
        return $kf->importSignatureKeyPair(
            new HiddenString(
                '31400500'
                . 'dc1a19af1bb72ac7aeccc783ef57ddb2fe2f849835d2a9a37f231384a533f07e'
                . '966ff16725e44754c78658920448a0593810623d5bc83ebd692ec0da07b6cea5'
                . 'f746b2817f90978ca70070d0a5c7cef8c6c68536210006df01ba4bc25378f135'
                . 'c1dcefd9708b0ef7ad659f4b80c9fd6030140352411f7540f2d54262f779f52c'
            )
        );
    }

    public function testEncrypt(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $plaintext = new HiddenString('foo');

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $asymmetricCrypto->encrypt(
            $plaintext,
            $ourKeyPair->getEncryptionKeyPair()->getSecretKey(),
            $theirKeyPair->getEncryptionKeyPair()->getPublicKey()
        );

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(172, strlen($ciphertext));
    }

    public function testDecrypt(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $ciphertext = 'MUIFAOlhnoKUBl0i6OOoB0hK5J_eGuw8MKv5X4TDDi-68H0lHOP8wNWv36pInB7fcgsnNVpa53wvJ3aV8E'
            . 'x7W3sxg_pX_iG4XrGod8xDBbzcWfkBetRjlu-cXjGBxMS1SluviOPbLkNMc6JxKWMa0XoiB0sL5-Ug8WaYWmI3iA==';

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $asymmetricCrypto->decrypt(
            $ciphertext,
            $theirKeyPair->getEncryptionKeyPair()->getSecretKey(),
            $ourKeyPair->getEncryptionKeyPair()->getPublicKey()
        );

        $this->assertTrue($plaintext->equals(new HiddenString('foo')));
    }

    public function testDecryptFailure(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getOtherKeyPair();
        $ciphertext = 'MUIFAOlhnoKUBl0i6OOoB0hK5J_eGuw8MKv5X4TDDi-68H0lHOP8wNWv36pInB7fcgsnNVpa53wvJ3aV8E'
            . 'x7W3sxg_pX_iG4XrGod8xDBbzcWfkBetRjlu-cXjGBxMS1SluviOPbLkNMc6JxKWMa0XoiB0sL5-Ug8WaYWmI3iA==';

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());

        $this->expectException(CryptoException::class);
        $asymmetricCrypto->decrypt(
            $ciphertext,
            $theirKeyPair->getEncryptionKeyPair()->getSecretKey(),
            $ourKeyPair->getEncryptionKeyPair()->getPublicKey()
        );
    }

    public function testEncryptFixedSize(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $plaintext = new HiddenString('bar');

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $asymmetricCrypto->encryptFixedSize(
            $plaintext,
            $ourKeyPair->getEncryptionKeyPair()->getSecretKey(),
            $theirKeyPair->getEncryptionKeyPair()->getPublicKey(),
            10
        );

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(180, strlen($ciphertext));
    }

    public function testDecryptFixedSize(): void
    {
        $ciphertext = 'MUIFAEEN4Meiusw0k_V02Bz1LCKAhHorX6uzqIz5IQ0mI9eQwcMoXkVlFrrTIwyKE1rhbmVn0-6ffcgXBZ7CbY'
            . 'RU5Ezfj9Yw6E9svr31EuSwcuW4M4SAWuCXib61iMcM83_ki9GO5dAqVSshcxKN2Dst5_ru3WmHYPBJm_3YGM3kYZ5T45sC';
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $asymmetricCrypto->decryptFixedSize(
            $ciphertext,
            $theirKeyPair->getEncryptionKeyPair()->getSecretKey(),
            $ourKeyPair->getEncryptionKeyPair()->getPublicKey()
        );

        $this->assertTrue($plaintext->equals(new HiddenString('bar')));
    }

    public function testSignAndEncrypt(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $plaintext = new HiddenString('foo');

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $asymmetricCrypto->signAndEncrypt(
            $plaintext,
            $ourKeyPair->getSecretKey(),
            $theirKeyPair->getPublicKey()
        );

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(256, strlen($ciphertext));
    }

    public function testVerifyAndDecrypt(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $ciphertext = 'MUIFAM7ZhAcR5_MUAhiMTM0g0aQ59SgcqyF-Jt0VewVhM7tumoYikkczuqYmD5SJfHn7lHmWEt-6HXFlg0LJFd'
            . 'RyGERdfm5ZU10Kjd9TUwkEb2syfoPx78ZwLhDYFRPHjq9tRC4pqz7vbmbUkmu2ATCPf6I3xFPE_ter96vOO_ZEYA9hO8YY'
            . 'gHpP_NZ9d0V_umGZf26KFJyTZlvWUDGCp-FkUhEZ8SkIW8zIJdL1fp2_JJ-P9PCo7Lfa0hiV1gc=';

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $asymmetricCrypto->verifyAndDecrypt(
            $ciphertext,
            $ourKeyPair->getPublicKey(),
            $theirKeyPair->getSecretKey()
        );

        $this->assertTrue($plaintext->equals(new HiddenString('foo')));
    }

    public function testVerifyAndDecryptFailure(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getOtherKeyPair();
        $ciphertext = 'MUIFAM7ZhAcR5_MUAhiMTM0g0aQ59SgcqyF-Jt0VewVhM7tumoYikkczuqYmD5SJfHn7lHmWEt-6HXFlg0LJFd'
            . 'RyGERdfm5ZU10Kjd9TUwkEb2syfoPx78ZwLhDYFRPHjq9tRC4pqz7vbmbUkmu2ATCPf6I3xFPE_ter96vOO_ZEYA9hO8YY'
            . 'gHpP_NZ9d0V_umGZf26KFJyTZlvWUDGCp-FkUhEZ8SkIW8zIJdL1fp2_JJ-P9PCo7Lfa0hiV1gc=';

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $this->expectException(CryptoException::class);
        $asymmetricCrypto->verifyAndDecrypt(
            $ciphertext,
            $ourKeyPair->getPublicKey(),
            $theirKeyPair->getSecretKey()
        );
    }

    public function testSignAndEncryptFixedSize(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $plaintext = new HiddenString('bar');

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $ciphertext = $asymmetricCrypto->signAndEncryptFixedSize(
            $plaintext,
            $ourKeyPair->getSecretKey(),
            $theirKeyPair->getPublicKey(),
            10
        );

        $this->assertStringStartsWith('MUIFA', $ciphertext);
        $this->assertEquals(268, strlen($ciphertext));
        // $this->assertEquals('0', $ciphertext);
    }

    public function testVerifyAndDecryptFixedSize(): void
    {
        $ourKeyPair = $this->getOurKeyPair();
        $theirKeyPair = $this->getTheirKeyPair();
        $ciphertext = 'MUIFA'
            . 'GvXCWFNLTFVSFW30lJxgOrl3TV515BfzVpWrFB9S74KRO--v8kRWRNKmJxe624RXSf'
            . 'hgj-pRsYoEEJTTuVmXFVkUeBlLKY44IaX6B8CiFnVl4lPq_oHUs7n6U6Kg8dUCX9DH'
            . 'obzO7dQ_h-6JwcDbomwzGbpQbiF4zN5l-kZMvkMeOyx9ETHn5YPfuMrE3soHP_6d1A'
            . 'zsI4vpyls6xFLFRtFZYhQQJFkTnAJkUR5WyvU2yos0hV74hAExFVxNz7Q5HVwxQ==';

        $asymmetricCrypto = new AsymmetricCrypto(new HiddenStringUtilities());
        $plaintext = $asymmetricCrypto->verifyAndDecryptFixedSize(
            $ciphertext,
            $ourKeyPair->getPublicKey(),
            $theirKeyPair->getSecretKey()
        );

        $this->assertTrue($plaintext->equals(new HiddenString('bar')));
    }
}

<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\KeyFactory;
use AdrianSuter\CryptoSuite\PasswordUtilities;
use AdrianSuter\CryptoSuite\SaltFactory;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

use function base64_decode;

class PasswordUtilitiesTest extends TestCase
{
    private function buildPasswordUtilities(): PasswordUtilities
    {
        $pepper = base64_decode('aW8/6a+Pld62aD24RnATJA==');
        $saltFactory = new SaltFactory($pepper, 99);
        $keyFactory = new KeyFactory($saltFactory);

        return new PasswordUtilities($keyFactory);
    }

    public function testDerivePasswordKey(): void
    {
        $passwordUtilities = $this->buildPasswordUtilities();

        $passwordKey = $passwordUtilities->derivePasswordKey(
            new HiddenString('foo'),
            base64_decode('Yrz6a0vr5oCitlq5/+EW2w==')
        );
        $this->assertEquals(
            'XRVAph+RjKZxd/53HsMk23tutFedxqNI0v0Rqb1KiyU=',
            base64_encode($passwordKey->getRawKeyMaterial())
        );
    }

    public function testGeneratePassword(): void
    {
        $passwordUtilities = $this->buildPasswordUtilities();
        $password = $passwordUtilities->generatePassword(16);
        $this->assertEquals(16, strlen($password->getString()));
    }
}

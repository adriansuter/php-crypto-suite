<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\SaltFactory;
use PHPUnit\Framework\TestCase;

class SaltFactoryTest extends TestCase
{
    private function buildSaltFactory()
    {
        return new SaltFactory('1234567890abcdef', 15);
    }

    public function testGenerateSalt(): void
    {
        $saltFactory = $this->buildSaltFactory();
        $this->assertIsString($saltFactory->generateSalt());
    }

    public function testGeneratePepperSalt(): void
    {
        $saltFactory = $this->buildSaltFactory();
        $this->assertIsString($saltFactory->generatePepperSalt());
    }

    public function testDerivePepperSalt(): void
    {
        $saltFactory = $this->buildSaltFactory();
        $this->assertEquals(
            '05edc8fcda4927e6',
            $saltFactory->derivePepperSalt(
                '1234567890abcdef'
            )
        );
    }
}

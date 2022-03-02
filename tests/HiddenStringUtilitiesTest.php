<?php

declare(strict_types=1);

namespace Test\AdrianSuter\CryptoSuite;

use AdrianSuter\CryptoSuite\HiddenStringUtilities;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;

class HiddenStringUtilitiesTest extends TestCase
{
    public function testPad(): void
    {
        $h = new HiddenStringUtilities();
        $this->assertEquals(
            '.hello....',
            $h->pad(new HiddenString('hello'), 9)->getString()
        );
    }

    public function testPadWithTrailingDot(): void
    {
        $h = new HiddenStringUtilities();
        $this->assertEquals(
            ',hello.,,,',
            $h->pad(new HiddenString('hello.'), 9)->getString()
        );
    }

    public function testPadSizeTooSmall(): void
    {
        $h = new HiddenStringUtilities();

        $this->expectException(\InvalidArgumentException::class);
        $h->pad(new HiddenString('hello'), 4);
    }

    /**
     * @return array<string[]>
     */
    public function trimDataProvider(): array
    {
        return [
            ['.hello', 'hello'],
            ['.hello..', 'hello'],
            [',hello.,', 'hello.'],
            ['.', ''],
            ['..', ''],
        ];
    }

    /**
     * @dataProvider trimDataProvider
     * @noinspection PhpDocSignatureInspection
     */
    public function testTrim(string $input, string $expected): void
    {
        $hiddenStringUtilities = new HiddenStringUtilities();
        $this->assertEquals(
            $expected,
            $hiddenStringUtilities->trim(new HiddenString($input))->getString()
        );
    }

    public function testTrimInvalidPadChar(): void
    {
        $hiddenStringUtilities = new HiddenStringUtilities();
        $this->expectException(\InvalidArgumentException::class);
        $hiddenStringUtilities->trim(new HiddenString('-hello--'));
    }
}

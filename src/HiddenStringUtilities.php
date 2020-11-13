<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite;

use ParagonIE\HiddenString\HiddenString;

final class HiddenStringUtilities
{
    /**
     * @param HiddenString $input
     * @param int $size
     * @return HiddenString
     */
    public function pad(HiddenString $input, int $size): HiddenString
    {
        $length = strlen($input->getString());
        if ($length > $size) {
            throw new InvalidArgumentException('Plaintext is too long.');
        }

        $padChar = '.';
        if ($length > 0 && substr($input->getString(), -1) === $padChar) {
            $padChar = ',';
        }

        return new HiddenString(
            $padChar . str_pad($input->getString(), $size, $padChar, STR_PAD_RIGHT)
        );
    }

    /**
     * @param HiddenString $input
     * @return HiddenString
     */
    public function trim(HiddenString $input): HiddenString
    {
        $padChar = substr($input->getString(), 0, 1);
        if ($padChar !== '.' && $padChar !== ',') {
            throw new InvalidArgumentException('Padding detection failed.');
        }

        return new HiddenString(
            rtrim(substr($input->getString(), 1), $padChar)
        );
    }
}

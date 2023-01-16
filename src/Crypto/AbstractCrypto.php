<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Crypto;

use AdrianSuter\CryptoSuite\HiddenStringUtilities;

abstract class AbstractCrypto
{
    /**
     * @var HiddenStringUtilities
     */
    protected HiddenStringUtilities $hiddenStringUtilities;

    /**
     * @param HiddenStringUtilities $hiddenStringUtilities
     */
    public function __construct(HiddenStringUtilities $hiddenStringUtilities)
    {
        $this->hiddenStringUtilities = $hiddenStringUtilities;
    }
}

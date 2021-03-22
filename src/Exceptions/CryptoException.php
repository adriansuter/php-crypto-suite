<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite\Exceptions;

use Exception;
use Throwable;

class CryptoException extends Exception
{
    public function __construct(?Throwable $previous = null)
    {
        parent::__construct('', 0, $previous);
    }
}

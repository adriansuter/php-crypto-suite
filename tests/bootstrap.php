<?php

declare(strict_types=1);

use AdrianSuter\Autoload\Override\Override;
use AdrianSuter\CryptoSuite\SaltFactory;

$classLoader = include(__DIR__ . '/../vendor/autoload.php');

$closures = [
    'random_bytes' => function (int $length): string {
        if (array_key_exists('random_bytes', $GLOBALS)) {
            if ($GLOBALS['random_bytes'] === 'exception') {
                throw new Exception();
            }
            return $GLOBALS['random_bytes'];
        }
        return random_bytes($length);
    },
];

Override::apply($classLoader, [
    SaltFactory::class => [
        'random_bytes' => $closures['random_bytes'],
    ],
]);

<?php

declare(strict_types=1);

namespace AdrianSuter\CryptoSuite;

use Exception;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

use function mb_strlen;
use function random_int;

class PasswordUtilities
{
    /**
     * @var KeyFactory
     */
    protected $keyFactory;

    /**
     * @param KeyFactory $keyFactory
     */
    public function __construct(KeyFactory $keyFactory)
    {
        $this->keyFactory = $keyFactory;
    }

    /**
     * @param HiddenString $password
     * @param string       $salt
     *
     * @return EncryptionKey
     *
     * @throws Exceptions\CryptoException
     */
    public function derivePasswordKey(HiddenString $password, string $salt): EncryptionKey
    {
        return $this->keyFactory->derivePepperedEncryptionKey($password, $salt);
    }

    /**
     * @param int    $length
     * @param string $keyspace
     *
     * @return HiddenString
     *
     * @throws Exception
     */
    public function generatePassword(
        int $length,
        string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ): HiddenString {
        $str = '';
        $max = mb_strlen($keyspace, 'UTF-8') - 1;

        if ($max < 1) {
            throw new Exception('$keyspace must be at least two characters long');
        }

        for ($i = 0; $i < $length; ++$i) {
            $str .= $keyspace[random_int(0, $max)];
        }

        return new HiddenString($str);
    }
}

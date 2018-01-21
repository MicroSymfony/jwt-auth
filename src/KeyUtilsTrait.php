<?php

namespace MicroSymfony\JWT;

trait KeyUtilsTrait
{
    protected function enrichKeyName($key)
    {
        if ('file://' !== substr($key, 0, 7) && file_exists($key)) {
            $key = 'file://'.realpath($key);
        }

        return $key;
    }
}

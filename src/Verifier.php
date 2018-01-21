<?php

namespace MicroSymfony\JWT;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use MicroSymfony\JWT\Exceptions\VerificationException;

class Verifier
{
    private $publicKey;

    public function __construct($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function verify(string $token, string $service)
    {
        $token = (new Parser())->parse($token);
        if ($this->getUid($service) !== $token->getClaim('uid') || !$this->verifyToken($token)) {
            throw new VerificationException();
        }

        return true;
    }

    public function verifyToken(Token $token): bool
    {
        $signer = new Sha256();
        $key = new Key($this->publicKey);

        $result = $token->verify($signer, $key);

        return $result;
    }

    private function getUid(string $service)
    {
        return substr(sha1(md5($service)), 0, 5);
    }

    public function setPublicKey(string $publicKey)
    {
        $this->publicKey = $publicKey;
    }
}

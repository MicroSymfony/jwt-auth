<?php

namespace MicroSymfony\JWT\Test;

use MicroSymfony\JWT\Exceptions\VerificationException;
use MicroSymfony\JWT\Signer;
use MicroSymfony\JWT\Verifier;
use PHPUnit\Framework\TestCase;

class VerifierTest extends TestCase
{
    public function testVerify()
    {
        $publicKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'public.pem');
        $service = 'testService';
        $verifier = new Verifier($publicKey);

        $token = $this->getToken($service);

        $this->assertTrue($verifier->verify($token, $service));
    }

    public function testVerifyBadService()
    {
        $publicKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'public.pem');
        $verifier = new Verifier($publicKey);

        $token = $this->getToken('testService');
        $this->expectException(VerificationException::class);

        $verifier->verify($token, 'service2');
    }

    public function testVerifyBadKey()
    {
        $publicKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'public.pem');
        $verifier = new Verifier($publicKey);

        $token = $this->getToken('testService');
        // lets mess up the token
        $token = strtoupper($token);
        $this->expectException(\RuntimeException::class);

        $verifier->verify($token, 'testService');
    }


    public function testVerifyInvalidKey()
    {
        $publicKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'public.pem');
        $verifier = new Verifier($publicKey);

        $token = $this->getToken('testService', 'private2.pem');
        $this->expectException(VerificationException::class);

        $verifier->verify($token, 'testService');
    }


    private function getToken($service, $key = 'private.pem')
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.$key);
        $passphase = '1111';
        $timeout = 3600;
        $allowedServices = [
            'testService',
        ];
        $allowedIpRanges = [
            '127.0.0.0/8',
        ];

        $signer = new Signer($privateKey, $passphase, $timeout, $allowedServices, $allowedIpRanges);
        $signer->setIssuer('PHPUnit.test');

        $token = $signer->sign($service, '127.0.0.1');

        return $token;
    }
}

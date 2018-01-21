<?php

namespace MicroSymfony\JWT\Test;

use MicroSymfony\JWT\Exceptions\UnauthorizedException;
use MicroSymfony\JWT\Signer;
use PHPUnit\Framework\TestCase;

class SignerTest extends TestCase
{
    public function testSign()
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'private.pem');
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

        $token = $signer->sign('testService', '127.0.0.1');

        $this->assertContains(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6InNlcnZpY2UtdGVzdFNlcnZpY2UtdG9rZW4ifQ.',
            $token
        );
    }

    public function testSignInvalidPassphase()
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'private.pem');
        $passphase = '';
        $timeout = 3600;
        $allowedServices = [
            'testService',
        ];
        $allowedIpRanges = [
            '127.0.0.0/8',
        ];

        $signer = new Signer($privateKey, $passphase, $timeout, $allowedServices, $allowedIpRanges);
        $signer->setIssuer('PHPUnit.test');

        $this->expectException(\InvalidArgumentException::class);
        $signer->sign('testService', '127.0.0.1');
    }

    public function testSignInvalidKey()
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'public.pem');
        $passphase = '1111';
        $timeout = 3600;
        $allowedServices = [
            'testService',
        ];
        $allowedIpRanges = [
            '10.0.0.0/8',
            '127.0.0.0/8',
        ];

        $signer = new Signer($privateKey, $passphase, $timeout, $allowedServices, $allowedIpRanges);
        $signer->setIssuer('PHPUnit.test');
        $this->expectException(\InvalidArgumentException::class);
        $signer->sign('testService', '127.0.0.1');
    }

    public function testSignNotAllowedService()
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'private.pem');
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
        $this->expectException(UnauthorizedException::class);
        $signer->sign('testService2', '127.0.0.1');
    }


    public function testSignNotAllowedIP()
    {
        $privateKey = 'file://'.realpath(__DIR__.DIRECTORY_SEPARATOR.'fixtures'.DIRECTORY_SEPARATOR.'private.pem');
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
        $this->expectException(UnauthorizedException::class);
        $signer->sign('testService', '128.0.0.1');
    }
}

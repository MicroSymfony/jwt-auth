<?php

namespace MicroSymfony\JWT\Test;

use MicroSymfony\Connection\ConnectionAdapters\ConnectionAdapterInterface;
use MicroSymfony\JWT\TokenManager;
use PHPUnit\Framework\TestCase;

class TokenManagerTest extends TestCase
{
    public function testGetToken()
    {
        $tokenMock = 'abcfff';
        $connection = $this->createMock(ConnectionAdapterInterface::class);
        $connection
            ->expects($this->once())
            ->method('get')
            ->willReturn(json_encode(['token' => $tokenMock]));

        $tokenManager = new TokenManager();
        // let's clear cache
        $tokenManager->getCache()->deleteItem('token');

        $tokenManager->setConnection($connection);

        $token = $tokenManager->getToken();
        $this->assertEquals($tokenMock, $token);
    }

    public function testGetTokenCached()
    {
        $tokenMock = 'abcfff';
        $connection = $this->createMock(ConnectionAdapterInterface::class);
        $connection
            ->expects($this->once())
            ->method('get')
            ->willReturn(json_encode(['token' => $tokenMock]));

        $tokenManager = new TokenManager();
        // let's clear cache
        $tokenManager->getCache()->deleteItem('token');

        $tokenManager->setConnection($connection);

        $token = $tokenManager->getToken();
        $this->assertEquals($tokenMock, $token);

        $token = $tokenManager->getToken();
        $this->assertEquals($tokenMock, $token);
    }

    public function testGetTokenNoCache()
    {
        $tokenMock = 'abcfff';
        $newTokenMock = 'ghhfhdf';
        $connection = $this->createMock(ConnectionAdapterInterface::class);
        $connection
            ->expects($this->exactly(2))
            ->method('get')
            ->willReturnOnConsecutiveCalls(
                json_encode(['token' => $tokenMock]),
                json_encode(['token' => $newTokenMock])
            );

        $tokenManager = new TokenManager();

        $tokenManager->setConnection($connection);

        $token = $tokenManager->getToken(false);
        $this->assertEquals($tokenMock, $token);

        $token = $tokenManager->getToken(false);
        $this->assertEquals($newTokenMock, $token);
    }

    public function testGetTokenError()
    {
        $connection = $this->createMock(ConnectionAdapterInterface::class);
        $connection
            ->expects($this->once())
            ->method('get')
            ->willReturn(json_encode(['error' => 'Testing']));

        $tokenManager = new TokenManager();

        $tokenManager->setConnection($connection);

        $this->expectException(\RuntimeException::class);
        $tokenManager->getToken(false);
    }
}

<?php

namespace MicroSymfony\JWT;

use MicroSymfony\Connection\ConnectionAdapters\ConnectionAdapterInterface;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class TokenManager
{
    /** @var ConnectionAdapterInterface */
    private $connection;

    /** @var AdapterInterface */
    private $cache;

    public function getToken($useCache = true)
    {
        $token = $this->getCached();
        if (empty($token) || !$useCache) {
            $token = $this->requestToken();
        }

        return $token;
    }

    private function getCached()
    {
        $cache = $this->getCache();

        return $cache->getItem('token')->get();
    }

    private function requestToken()
    {
        $response = $this->connection->get('auth');
        $tokenData = json_decode($response, true);
        $this->checkToken($tokenData);
        $this->cacheToken($tokenData['token']);

        return $tokenData['token'];
    }

    private function checkToken($token)
    {
        if (null === $token || !isset($token['token'])) {
            throw new \RuntimeException(sprintf('Failed to request token: %s', $token['error'] ?? ''));
        }
    }

    private function cacheToken($token)
    {
        $cache = $this->getCache();
        $cached = $cache->getItem('token');
        $cached->set($token);
        $cache->save($cached);
    }

    public function getCache()
    {
        if (null === $this->cache) {
            $this->cache = new FilesystemAdapter('app.cache');
        }

        return $this->cache;
    }

    /**
     * @param ConnectionAdapterInterface $connection
     */
    public function setConnection(ConnectionAdapterInterface $connection): void
    {
        $this->connection = $connection;
    }
}

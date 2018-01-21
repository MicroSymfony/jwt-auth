<?php

namespace MicroSymfony\JWT;

use MicroSymfony\Connection\ConnectionAdapters\ConnectionAdapterInterface;

class TokenManager
{
    /** @var ConnectionAdapterInterface */
    private $connection;

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
        $shm = shm_attach(1, 1024);
        $token = shm_get_var($shm, 1);

        return $token;
    }

    private function requestToken()
    {
        $response = $this->connection->get('auth');
        $tokenData = json_decode($response);
        if (null === $tokenData || !isset($tokenData['token'])) {
            throw new \RuntimeException(sprintf('Failed to request token: %s', $tokenData['error'] ?? ''));
        }
        $shm = shm_attach(1, 1024);
        shm_put_var($shm, 1, $tokenData['token']);

        return $tokenData['token'];
    }
}

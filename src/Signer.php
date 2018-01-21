<?php

namespace MicroSymfony\JWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use MicroSymfony\JWT\Exceptions\UnauthorizedException;

class Signer
{
    use KeyUtilsTrait;

    private $allowedServices = [];
    private $allowedIpRanges = [];
    private $passphrase = '';
    private $timeout = 3600;
    private $privateKey = '';
    private $issuer = '';

    public function __construct($privateKey, $passphrase, $timeout, $allowedServices, $allowedIpRanges)
    {
        $this->privateKey = $privateKey;
        $this->passphrase = $passphrase;
        $this->timeout = $timeout;
        $this->allowedServices = $allowedServices;
        $this->allowedIpRanges = $allowedIpRanges;
    }

    public function sign(string $service, string $ip): string
    {
        $signer = new Sha256();
        // PHP seems to have an issue when there are no file:// in beginning
        $fullKey = $this->enrichKeyName($this->privateKey);
        $key = new Key($fullKey, $this->passphrase);

        $this->verifyService($service, $ip);

        $token = (new Builder())->setIssuer($this->issuer)
            ->setId(sprintf('service-%s-token', $service), true)
            ->setIssuedAt(time())
            ->setExpiration(time() + $this->timeout)
            ->set('uid', $this->getUid($service))
            ->sign($signer, $key)
            ->getToken();

        return (string) $token;
    }

    private function getUid(string $service)
    {
        return substr(sha1(md5($service)), 0, 5);
    }

    private function verifyService(string $service, string $ip)
    {
        if (!$this->isServiceAllowed($service) || !$this->isIpAllowed($ip)) {
            throw new UnauthorizedException();
        }
    }

    private function isServiceAllowed(string $service)
    {
        return in_array($service, $this->allowedServices);
    }

    private function isIpAllowed(string $ip)
    {
        $result = false;
        foreach ($this->allowedIpRanges as $range) {
            $result = $this->isIpInRange($ip, $range);
            if ($result) {
                break;
            }
        }

        return $result;
    }

    private function isIpInRange($ip, $range)
    {
        if (false === strpos($range, '/')) {
            $range .= '/32';
        }
        // $range is in IP/CIDR format eg 127.0.0.1/24
        list($range, $mask) = explode('/', $range, 2);
        $rangeDecimal = ip2long($range);
        $ipDecimal = ip2long($ip);
        $wildcardDecimal = pow(2, (32 - $mask)) - 1;
        $maskDecimal = ~ $wildcardDecimal;

        return (($ipDecimal & $maskDecimal) === ($rangeDecimal & $maskDecimal));
    }

    /**
     * @param string $issuer
     */
    public function setIssuer(string $issuer): void
    {
        $this->issuer = $issuer;
    }
}

<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Analytics
{
    public function __construct(
        private readonly bool $trackingEnabled,
        private readonly LoggerInterface $logger
    )
    {
    }

    /**
     * FIXED: SSRF + RCE — the referer is no longer passed to a shell command
     * (which allowed arbitrary command execution). The URL is strictly
     * validated (http/https only, no internal/private targets) and fetched with
     * the cURL extension, never through shell_exec.
     */
    public function track(): void {
        if (!$this->trackingEnabled) {
            return;
        }

        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        if (!$referer || !$this->validate($referer)) {
            return;
        }

        if (!\function_exists('curl_init')) {
            return;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $referer,
            CURLOPT_NOBODY => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            // Restrict the protocols cURL is allowed to speak to avoid
            // file://, gopher://, dict://, etc. being abused.
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ]);

        curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $this->logger->info('Referer URL response status: ' . $statusCode);
    }

    /**
     * Only allow public http/https URLs and reject any host that resolves to a
     * private, loopback or reserved IP range (SSRF protection).
     */
    public function validate(string $url): bool
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $parts = parse_url($url);
        if (!isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return false;
        }

        return $this->isPublicHost($parts['host']);
    }

    private function isPublicHost(string $host): bool
    {
        // Resolve the host to its IP addresses and make sure none of them point
        // to an internal/reserved range.
        $ips = [];

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            if ($records === false || $records === []) {
                return false;
            }
            foreach ($records as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                }
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        if ($ips === []) {
            return false;
        }

        foreach ($ips as $ip) {
            if (!filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            )) {
                return false;
            }
        }

        return true;
    }
}

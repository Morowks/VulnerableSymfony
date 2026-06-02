<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Avatar
{

    public function __construct(
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * FIXED: SSRF — instead of calling file_get_contents() on an arbitrary URL
     * (which allows file://, php://, internal hosts, etc.), the URL is strictly
     * validated (http/https only, public hosts only) and fetched through cURL
     * with the allowed protocols restricted.
     */
    public function getFromUrl(string $url): string|false
    {
        if (!$this->isAllowedUrl($url) || !\function_exists('curl_init')) {
            $this->logger->error('Rejected avatar URL (SSRF protection): ' . $url);
            return false;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_MAXFILESIZE => 5 * 1024 * 1024,
        ]);

        $content = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($content === false || $statusCode < 200 || $statusCode >= 300) {
            $this->logger->error('Error getting avatar from URL: ' . $error);
            return false;
        }

        return $content;
    }

    private function isAllowedUrl(string $url): bool
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

        $ips = [];
        if (filter_var($parts['host'], FILTER_VALIDATE_IP)) {
            $ips[] = $parts['host'];
        } else {
            $records = @dns_get_record($parts['host'], DNS_A | DNS_AAAA);
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

<?php

declare(strict_types=1);

namespace Core\Mail\Service;

use DOMDocument;
use DOMXpath;
use JsonException;

/**
 * @see Fork by https://github.com/hbattat/verifyEmail/blob/master/src/VerifyEmail.php
 *
 * SImple Used: $isValid = $this->mailVerifyService->verify($email, $verifier);
 */
final class MailVerifyService
{
    #region CONSTANTS
    /** @var string */
    private const YAHOO_SERVICE = 'yahoo';
    /** @var string */
    private const HOTMAIL_SERVICE = 'hotmail';
    /** @var string */
    private const USER_AGENT = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) '
    . 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36';
    /** @var string */
    private const YAHOO_SIGNUP_PAGE_URL = 'https://login.yahoo.com/account/create'
    . '?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login';
    /** @var string */
    private const YAHOO_SIGNUP_AJAX_URL = 'https://login.yahoo.com/account/module/create?validateField=yid';
    /** @var array<int,string> */
    private const YAHOO_DOMAINS = ['yahoo.com'];
    /** @var string */
    private const HOTMAIL_SIGNIN_PAGE_URL = 'https://login.live.com/';
    /** @var string */
    private const HOTMAIL_USERNAME_CHECK_URL = 'https://login.live.com/GetCredentialType.srf?wa=wsignin1.0';
    /** @var array<int,string> */
    private const HOTMAIL_DOMAINS = ['hotmail.com', 'live.com', 'outlook.com', 'msn.com'];
    /** @var int */
    private const SOCKET_PORT = 25;
    #endregion

    #region PROPERTIES
    /** @var string */
    private $email = '';
    /** @var array<int,string> */
    private $logData = [];
    /** @var string */
    private $pageContent = '';
    /** @var array<int,string> */
    private $pageHeaders = [];
    #endregion

    #region PUBLIC METHODS
    /**
     * @throws JsonException
     */
    public function verify(string $email = '', string $verifierEmail = ''): bool
    {
        $isValid = false;

        $this->addLogRow("................................");
        $this->addLogRow(">> Verify function was called >>");
        $this->addLogRow("................................");

        $this->email = $email;
        $this->addLogRow("Email was set to `$email`");
        $this->addLogRow("Verifier Email was set to `$verifierEmail`");

        // fast check
        if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $this->addLogRow("Fast check `$this->email` failed");
            return false;
        }

        $domain = $this->getDomain($this->email);
        if (in_array(strtolower($domain), self::YAHOO_DOMAINS, true)) {
            $isValid = $this->validateYahoo();
        } elseif (in_array(strtolower($domain), self::HOTMAIL_DOMAINS, true)) {
            $isValid = $this->validateHotmail();
        } else {
            $this->addLogRow("Finding MX record...");

            $mxIp = $this->findMx();
            if (!$mxIp) {
                $this->addLogRow("No MX record was found.");
                return false;
            }

            $this->addLogRow("Found MX: $mxIp");

            $this->addLogRow("Connecting to the server...");
            $connect = $this->connectMx($mxIp);

            if (!$connect) {
                $this->addLogRow("Connection to server failed.");
                return false;
            }

            $this->addLogRow("Connection to server was successful.");

            $this->addLogRow("Starting verification...");
            if (0 === strpos((string)fgets($connect), "220")) {
                // ИМЕННО "HELO" не "HELLO" - это ВАЖНО !
                $this->addLogRow("Got a 220 response. Sending HELO...");
                fwrite($connect, "HELO " . $this->getDomain($verifierEmail) . "\r\n");
                $out = (string) fgets($connect);
                $this->addLogRow("Response: $out"); // $this->addLogRow("");

                $this->addLogRow("Sending MAIL FROM...");
                fwrite($connect, "MAIL FROM: <$verifierEmail>\r\n");
                $from = (string) fgets($connect);
                $this->addLogRow("Response: $from");

                $this->addLogRow("Sending RCPT TO...");
                fwrite($connect, "RCPT TO: <$this->email>\r\n");
                $to = (string) fgets($connect);
                $this->addLogRow("Response: $to");

                $this->addLogRow("Sending QUIT...");
                $quit = (string) fwrite($connect, "QUIT");
                $this->addLogRow("Response: $quit");
                fclose($connect);

                $this->addLogRow("Looking for 250 response...");
                if (0 !== strpos($from, "250") || 0 !== strpos($to, "250")) {
                    $this->addLogRow("Not found! Email is invalid.");
                } else {
                    $this->addLogRow("Found! Email is valid.");
                    $isValid = true;
                }
            } else {
                $this->addLogRow("Encountered an unknown response code.");
            }
        }

        return $isValid;
    }

    /**
     * @return array<int,string>
     */
    public function getLogData(): array
    {
        return $this->logData;
    }
    #endregion

    #region PRIVATE METHODS
    private function addLogRow(string $value): void
    {
        $this->logData[] = $value;
    }

    private function getDomain(string $email): string
    {
        $email_arr = explode('@', $email);
        $domain = array_slice($email_arr, -1);
        return $domain[0];
    }

    private function findMx(): string
    {
        $domain = $this->getDomain($this->email);
        $mxIp = null;
        // Trim [ and ] from beginning and end of domain string, respectively
        $domain = ltrim($domain, '[');
        $domain = rtrim($domain, ']');

        if (strpos($domain, 'IPv6:') === 0) {
            $domain = substr($domain, strlen('IPv6') + 1);
        }

        $mxHosts = $mxWeight = [];
        if (filter_var($domain, FILTER_VALIDATE_IP)) {
            $mxIp = $domain;
        } else {
            getmxrr($domain, $mxHosts, $mxWeight);
        }

        if (!empty($mxHosts)) {
            $mxIp = $mxHosts[array_search(min($mxWeight), $mxWeight, true)] ?? null;
        } else {
            $dnsRecord = false;
            if (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $dnsRecord = dns_get_record($domain, DNS_A);
            } elseif (filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $dnsRecord = dns_get_record($domain, DNS_AAAA);
            }

            if (!empty($dnsRecord)) {
                $mxIp = $dnsRecord[0]['ip'] ?? null;
            }
        }

        return $mxIp;
    }

    /**
     * @return resource|false
     */
    private function connectMx(string $mxIp)
    {
        return fsockopen($mxIp, self::SOCKET_PORT);
    }

    /**
     * @throws JsonException
     */
    private function validateYahoo(): bool
    {
        $this->addLogRow("Validating a yahoo email address...");
        $this->addLogRow("Getting the sign up page content...");
        $this->fetchPage(self::YAHOO_SERVICE);

        $cookies = $this->getCookies();
        $fields = $this->getFields();

        $this->addLogRow("Adding the email to fields...");
        $fields['yid'] = str_replace('@yahoo.com', '', strtolower($this->email));

        $this->addLogRow("Ready to submit the POST request to validate the email.");

        $response = $this->requestValidation(self::YAHOO_SERVICE, $cookies, $fields);

        $this->addLogRow("Parsing the response...");
        $jsonResponse = (array) json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        $responseErrors = $jsonResponse['errors'] ?? [];

        $this->addLogRow("Searching errors for existing username error...");
        foreach ($responseErrors as $err) {
            $errName = isset($err['name']) ? (string) $err['name'] : null;
            $errCode = isset($err['error']) ? (string) $err['error'] : null;
            if ($errName === 'yid' && $errCode === 'IDENTIFIER_EXISTS') {
                $this->addLogRow("Found an error about existing email.");
                return true;
            }
        }

        return false;
    }

    /**
     * @throws JsonException
     */
    private function validateHotmail(): bool
    {
        $this->addLogRow("Validating a hotmail email address...");
        $this->addLogRow("Getting the sign up page content...");
        $this->fetchPage(self::HOTMAIL_SERVICE);
        $cookies = $this->getCookies();

        $this->addLogRow("Sending another request to get the needed cookies for validation...");
        $this->fetchPage(self::HOTMAIL_SERVICE, implode(' ', $cookies));
        $cookies = $this->getCookies();

        $this->addLogRow("Preparing fields...");
        $fields = $this->prepHotmailFields($cookies);

        $this->addLogRow("Ready to submit the POST request to validate the email.");
        $response = $this->requestValidation(self::HOTMAIL_SERVICE, $cookies, $fields);

        $this->addLogRow("Searching username error...");
        $jsonResponse = (array) json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        if (empty($jsonResponse['IfExistsResult'])) {
            return true;
        }

        return false;
    }

    /**
     * @param string $cookies
     * @return resource A stream context resource
     */
    private function getContext(string $cookies)
    {
        $opts = [
            'http' => [
                'method' => "GET",
                'header' => "Accept-language: en\r\n" .
                    "Cookie: {$cookies}\r\n"
            ]
        ];
        return stream_context_create($opts);
    }

    private function fetchPage(string $service, string $cookies = ''): void
    {
        $context = $cookies ? $this->getContext($cookies) : null ;

        $http_response_header = null; // https://www.php.net/manual/ru/reserved.variables.httpresponseheader.php
        if ($service === self::YAHOO_SERVICE) {
            if ($cookies) {
                $this->pageContent = (string) file_get_contents(self::YAHOO_SIGNUP_PAGE_URL, false, $context);
            } else {
                $this->pageContent = (string) file_get_contents(self::YAHOO_SIGNUP_PAGE_URL);
            }
        } elseif ($service === self::HOTMAIL_SERVICE) {
            if ($cookies) {
                $this->pageContent = (string) file_get_contents(self::HOTMAIL_SIGNIN_PAGE_URL, false, $context);
            } else {
                $this->pageContent = (string) file_get_contents(self::HOTMAIL_SIGNIN_PAGE_URL);
            }
        }

        if (!$this->pageContent) {
            $this->addLogRow("Could not read the sign up page.");
        } else {
            $this->addLogRow("Sign up page content stored.");
            $this->addLogRow("Getting headers...");
            $this->pageHeaders = (array) $http_response_header;
            $this->addLogRow("Sign up page headers stored.");
        }
    }

    /**
     * @return array<int,string>
     */
    private function getCookies(): array
    {
        $this->addLogRow("Attempting to get the cookies from the sign up page...");

        if ($this->pageContent) {
            $this->addLogRow("Extracting cookies from headers...");
            $cookies = [];

            foreach ($this->pageHeaders as $hdr) {
                if (preg_match('/^Set-Cookie:\s*(.*?;).*?$/i', $hdr, $matches)) {
                    $cookies[] = (string) $matches[1];
                }
            }

            if (count($cookies) > 0) {
                $this->addLogRow("Cookies found: " . implode(' ', $cookies));
                return $cookies;
            }

            $this->addLogRow("Could not find any cookies.");
        }

        return [];
    }

    /**
     * @return array<string,string>
     */
    private function getFields(): array
    {
        $dom = new DOMDocument();
        $fields = [];

        if (@$dom->loadHTML($this->pageContent)) {
            $this->addLogRow("Parsing the page for input fields...");
            $xp = new DOMXpath($dom);
            $nodes = (array) $xp->query('//input');
            foreach ($nodes as $node) {
                $fields[(string) $node->getAttribute('name')] = (string) $node->getAttribute('value');
            }

            $this->addLogRow("Extracted fields.");
        } else {
            $this->addLogRow("Something is worng with the page HTML.");
        }

        return $fields;
    }

    /**
     * @param string $service
     * @param array<int,string> $cookies
     * @param array<string,string> $fields
     * @return string
     * @throws \JsonException
     */
    private function requestValidation(string $service, array $cookies, array $fields): string
    {
        $result = '';

        if ($service === self::YAHOO_SERVICE) {
            $headers = [];
            $headers[] = 'Origin: https://login.yahoo.com';
            $headers[] = 'X-Requested-With: XMLHttpRequest';
            $headers[] = self::USER_AGENT;
            $headers[] = 'content-type: application/x-www-form-urlencoded; charset=UTF-8';
            $headers[] = 'Accept: */*';
            $headers[] = 'Referer: https://login.yahoo.com/account/create?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login'; // phpcs:ignore
            $headers[] = 'Accept-Encoding: gzip, deflate, br';
            $headers[] = 'Accept-Language: en-US,en;q=0.8,ar;q=0.6';

            $cookies_str = implode(' ', $cookies);
            $headers[] = "Cookie: $cookies_str";

            $postData = http_build_query($fields);

            $opts = [
                'http' =>
                    [
                        'method'  => 'POST',
                        'header'  => $headers,
                        'content' => $postData
                    ]
            ];

            $context  = stream_context_create($opts);
            $result = (string) file_get_contents(self::YAHOO_SIGNUP_AJAX_URL, false, $context);
        } elseif ($service === self::HOTMAIL_SERVICE) {
            $headers = [];
            $headers[] = 'Origin: https://login.live.com';
            $headers[] = 'hpgid: 33';
            $headers[] = self::USER_AGENT;
            $headers[] = 'Content-type: application/json; charset=UTF-8';
            $headers[] = 'Accept: application/json';
            $headers[] = 'Referer: https://login.live.com';
            $headers[] = 'Accept-Encoding: gzip, deflate, br';
            $headers[] = 'Accept-Language: en-US,en;q=0.8,ar;q=0.6';

            $cookies_str = implode(' ', $cookies);
            $headers[] = "Cookie: $cookies_str";

            $postData = json_encode($fields, JSON_THROW_ON_ERROR);

            $opts = [
                'http' =>
                    [
                        'method'  => 'POST',
                        'header'  => $headers,
                        'content' => $postData
                    ]
            ];

            $context  = stream_context_create($opts);
            $result = (string) file_get_contents(self::HOTMAIL_USERNAME_CHECK_URL, false, $context);
        }

        return $result;
    }

    /**
     * @param array<int,string> $cookies
     * @return array<string,string>
     */
    private function prepHotmailFields(array $cookies): array
    {
        $fields = [];
        foreach ($cookies as $cookie) {
            [$key, $val] = explode('=', $cookie, 2);
            if ($key === 'uaid') {
                $fields['uaid'] = $val;
                break;
            }
        }
        $fields['username'] = strtolower($this->email);

        return $fields;
    }
    #endregion
}
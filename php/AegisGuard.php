<?php
/**
 * AegisPHP — UK-Compliant Bot, IP, Header & Behavioral Input Defense Middleware
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 * Target Runtime: PHP 8.1+ (Zero external Composer dependencies required)
 *
 * Lawful Basis:
 * - UK GDPR Article 6(1)(f) & Recital 49 (Legitimate Interests: Network & Information Security)
 * - Data Protection Act 2018 (UK)
 * - PECR Regulation 6(4) (Strictly Necessary Security & Fraud Prevention Screening)
 */

declare(strict_types=1);

namespace AegisSecurity;

use PDO;
use RuntimeException;

final class AegisGuard
{
    private const BLOCK_THRESHOLD         = 65;
    private const CHALLENGE_THRESHOLD     = 35;
    private const CRITICAL_RISK_THRESHOLD = 85;
    private const ENABLE_CRITICAL_ALERTS  = true;
    private const ALERT_EMAIL_ADDRESS     = 'secops-alerts@yourdomain.co.uk';
    private const MAX_INPUT_ENTROPY       = 4.45;
    private const MAX_EMAIL_ENTROPY       = 4.05;
    private const MIN_TYPING_MS           = 1400;
    private const MAX_URLS_ALLOWED        = 2;
    private const LOG_RETENTION_DAYS      = 30;

    private const DISPOSABLE_DOMAINS = [
        'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'tempmail.com',
        'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'maildrop.cc',
        'throwawaymail.com'
    ];

    private const HIGH_RISK_CIDRS = [
        '185.220.101.0/24', // Tor Exit Subnet
        '45.142.214.0/24',  // Bulletproof Relay Subnet
        '194.165.16.0/24',  // Spamhaus DROP Listed
    ];

    private string $dailyHmacSalt;
    private ?PDO $pdo;
    private string $organizationName;
    private string $icoRegNumber;
    private string $dpoContact;

    public function __construct(
        ?PDO $pdo = null,
        ?string $secretKey = null,
        string $organizationName = 'BuruOps Protected Service',
        string $icoRegNumber = 'ZB491820',
        string $dpoContact = 'dpo-security@buruops.local'
    ) {
        $this->pdo = $pdo;
        $this->organizationName = $organizationName;
        $this->icoRegNumber = $icoRegNumber;
        $this->dpoContact = $dpoContact;

        // Daily rotating cryptographic salt ensures IP hashes cannot be correlated across days (UK GDPR Data Minimisation)
        $appSecret = $secretKey ?? ($_ENV['AEGIS_HMAC_SECRET'] ?? 'change-me-in-production-uk-gdpr-key');
        $this->dailyHmacSalt = hash_hmac('sha256', gmdate('Y-m-d'), $appSecret);
    }

    /**
     * Screens an incoming POST request (SMTP mailer form, Direct Message, Contact, or API).
     *
     * @param array<string, mixed> $post   Typically $_POST
     * @param array<string, mixed> $server Typically $_SERVER
     * @param string               $channel 'smtp_mail' | 'direct_message' | 'contact_form' | 'api_webhook'
     * @return array{audit_id: string, verdict: string, score: int, critical_alert_sent: bool, safe_for_smtp: bool, safe_for_dm: bool, flags: list<string>}
     */
    public function screenRequest(array $post, array $server, string $channel = 'smtp_mail'): array
    {
        $flags = [];
        $clientIp = (string) ($server['REMOTE_ADDR'] ?? '0.0.0.0');
        $email    = (string) ($post['email'] ?? '');
        $subject  = (string) ($post['subject'] ?? '');
        $message  = (string) ($post['message'] ?? '');

        // 1. IP Reputation & DNSBL Inspection
        $ipScore = $this->evaluateIpReputation($clientIp, $flags);

        // 2. Email Format, Entropy & SMTP Header Injection Hygiene
        $emailScore = $this->evaluateEmailAndSmtpSafety($email, $subject, $flags);

        // 3. Behavioral Telemetry, Shannon Entropy & Malicious Payload Inspection
        $behaviorScore = $this->evaluateBehaviorAndPayload($subject, $message, $post, $flags);

        // 4. Unexpected HTTP Request Headers Inspection
        $headerScore = $this->evaluateHttpHeaders($server, $channel, $flags);

        // Composite Risk Calculation
        $maxVector = max($ipScore, $emailScore, $behaviorScore, $headerScore);
        $weighted  = (int) round(($ipScore * 0.25) + ($emailScore * 0.25) + ($behaviorScore * 0.30) + ($headerScore * 0.20));
        $totalScore = min(100, (int) round(($maxVector * 0.65) + ($weighted * 0.55)));

        // Enforce UK Compliance Screening Banner Agreement
        $bannerAgreed = !empty($post['_aegis_uk_screen_ack']) || !empty($_COOKIE['aegis_uk_screen_ack']);
        if (!$bannerAgreed) {
            $totalScore = max($totalScore, self::CHALLENGE_THRESHOLD + 10);
            $flags[] = 'UK Regulatory Screening Notice not acknowledged by client';
        }

        $verdict = 'ALLOW';
        if ($totalScore >= self::BLOCK_THRESHOLD) {
            $verdict = 'BLOCK';
        } elseif ($totalScore >= self::CHALLENGE_THRESHOLD) {
            $verdict = 'CHALLENGE';
        }

        $auditId  = 'AEGIS-' . strtoupper(bin2hex(random_bytes(4)));
        $pseudoIp = $this->pseudonymiseIp($clientIp);

        // Trigger Critical Risk Email Notification if score reaches or exceeds CRITICAL_RISK_THRESHOLD
        $criticalAlertSent = false;
        if (self::ENABLE_CRITICAL_ALERTS && $totalScore >= self::CRITICAL_RISK_THRESHOLD && self::ALERT_EMAIL_ADDRESS !== '') {
            $criticalAlertSent = $this->dispatchCriticalRiskAlert(
                $auditId,
                $channel,
                $verdict,
                $totalScore,
                $pseudoIp,
                $email,
                $flags
            );
        }

        // Protective Audit Logging (Pseudonymised under UK GDPR Art. 6(1)(f))
        $this->recordProtectiveAuditLog(
            $auditId,
            $channel,
            $verdict,
            $totalScore,
            $pseudoIp,
            $email,
            $flags,
            $criticalAlertSent
        );

        return [
            'audit_id'            => $auditId,
            'verdict'             => $verdict,
            'score'               => $totalScore,
            'critical_alert_sent' => $criticalAlertSent,
            'safe_for_smtp'       => ($verdict === 'ALLOW' && $emailScore < 50),
            'safe_for_dm'         => ($verdict === 'ALLOW' && $behaviorScore < 50),
            'flags'               => $flags,
        ];
    }

    /**
     * Vector 1: IP Reputation & DNSBL Check
     */
    private function evaluateIpReputation(string $ip, array &$flags): int
    {
        $score = 0;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $flags[] = 'Invalid or malformed REMOTE_ADDR IP literal';
            return 65;
        }

        foreach (self::HIGH_RISK_CIDRS as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                $score += 70;
                $flags[] = "IP matches high-risk Tor/Bulletproof subnet ({$cidr})";
                break;
            }
        }

        // DNSBL check (Spamhaus Zen query for IPv4)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $reverseIp = implode('.', array_reverse(explode('.', $ip)));
            if (@checkdnsrr($reverseIp . '.zen.spamhaus.org.', 'A')) {
                $score += 45;
                $flags[] = 'Client IP listed in Spamhaus ZEN DNSBL';
            }
        }

        return min(100, $score);
    }

    /**
     * Vector 2: Suspicious Email Format & SMTP Header Injection Prevention
     */
    private function evaluateEmailAndSmtpSafety(string $email, string $subject, array &$flags): int
    {
        $score = 0;

        // Detect SMTP Header Injection (CRLF, Bcc:, Cc:, Content-Type:) before PHPMailer / mail()
        if (preg_match('/(\\\\r|\\\\n|%0a|%0d|[\\r\\n]|\\b(bcc|cc|content-type|mime-version|to)\\s*:)/i', $email . ' ' . $subject)) {
            $score += 95;
            $flags[] = 'CRITICAL: SMTP Header / CRLF Injection attempt blocked';
        }

        $cleanEmail = trim($email);
        if (!filter_var($cleanEmail, FILTER_VALIDATE_EMAIL)) {
            $score += 65;
            $flags[] = 'Malformed RFC 5322 email address';
            return min(100, $score);
        }

        [$local, $domain] = explode('@', strtolower($cleanEmail), 2);

        if (in_array($domain, self::DISPOSABLE_DOMAINS, true)) {
            $score += 75;
            $flags[] = "Disposable email provider blocked ({$domain})";
        }

        $localEntropy = $this->shannonEntropy($local);
        if ($localEntropy > self::MAX_EMAIL_ENTROPY && strlen($local) >= 9) {
            $score += 38;
            $flags[] = sprintf('High-entropy randomized email local-part (%.2f bits)', $localEntropy);
        }

        if (substr_count($local, '.') >= 4) {
            $score += 42;
            $flags[] = 'Suspicious dot-splitting evasion in email local-part';
        }

        if (preg_match('/\\+[a-z0-9]{4,}/i', $local)) {
            $score += 28;
            $flags[] = 'Automated sub-addressing (+tag) alias detected';
        }

        if (!@checkdnsrr($domain . '.', 'MX')) {
            $score += 40;
            $flags[] = "Domain ({$domain}) has no valid MX mail exchange records";
        }

        return min(100, $score);
    }

    /**
     * Vector 3: Behavioral Telemetry, Input Entropy & Malicious Payload Heuristics
     */
    private function evaluateBehaviorAndPayload(string $subject, string $message, array $post, array &$flags): int
    {
        $score = 0;
        $combined = $subject . ' ' . $message;

        // Honeypot Trap Check
        if (!empty($post['_aegis_hp_website'])) {
            $score += 95;
            $flags[] = 'Hidden honeypot trap field populated by automated bot';
        }

        // SQLi / XSS / PHP Object & Code Injection Signatures
        if (preg_match('/(\\bUNION\\s+(ALL\\s+)?SELECT\\b|\\bOR\\s+1\\s*=\\s*1\\b|\\bDROP\\s+TABLE\\b|\\bSLEEP\\s*\\(\\d+\\))/i', $combined)) {
            $score += 85;
            $flags[] = 'SQL Injection (SQLi) payload pattern detected';
        }
        if (preg_match('/(<script\\b|javascript:|onerror\\s*=|<\\?php|\\b(eval|system|passthru|shell_exec|base64_decode)\\s*\\(|O:\\d+:"[a-z0-9_]+":)/i', $combined)) {
            $score += 90;
            $flags[] = 'XSS or PHP Code/Object Serialization injection detected';
        }

        // URL Spam Link Density (Protects DM & Outbound SMTP Reputation)
        $urlCount = preg_match_all('/https?:\\/\\/[^\\s]+/i', $message);
        if ($urlCount > self::MAX_URLS_ALLOWED) {
            $score += 45;
            $flags[] = "Excessive URL count ({$urlCount} links exceed limit of " . self::MAX_URLS_ALLOWED . ")";
        }

        // Shannon Entropy & Keyboard Mash Detection
        $entropy = $this->shannonEntropy($message);
        if ($entropy > self::MAX_INPUT_ENTROPY && strlen($message) >= 16) {
            $score += 42;
            $flags[] = sprintf('High payload Shannon entropy (%.2f bits/char)', $entropy);
        }

        if ($this->isKeyboardMashOrGibberish($message)) {
            $score += 50;
            $flags[] = 'Random keyboard mashing or unnatural consonant cluster detected';
        }

        // Client Behavioral Telemetry Check
        $typingMs = (int) ($post['_aegis_typing_ms'] ?? 0);
        if ($typingMs > 0 && $typingMs < self::MIN_TYPING_MS && strlen($message) > 15) {
            $score += 48;
            $flags[] = "Superhuman form fill speed ({$typingMs}ms < " . self::MIN_TYPING_MS . "ms)";
        }

        return min(100, $score);
    }

    /**
     * Vector 4: Unexpected HTTP Request Headers
     */
    private function evaluateHttpHeaders(array $server, string $channel, array &$flags): int
    {
        $score = 0;
        $ua          = (string) ($server['HTTP_USER_AGENT'] ?? '');
        $acceptLang  = (string) ($server['HTTP_ACCEPT_LANGUAGE'] ?? '');
        $secFetchSite = (string) ($server['HTTP_SEC_FETCH_SITE'] ?? '');
        $xff         = (string) ($server['HTTP_X_FORWARDED_FOR'] ?? '');

        if ($ua === '') {
            $score += 65;
            $flags[] = 'Missing HTTP User-Agent header';
        } elseif (preg_match('/(python-requests|curl\\/|wget\\/|go-http-client|headlesschrome|phantomjs|scrapy)/i', $ua)) {
            $score += 75;
            $flags[] = 'Automated bot/script User-Agent signature detected';
        }

        if ($acceptLang === '') {
            $score += 35;
            $flags[] = 'Missing Accept-Language header';
        }

        if ($secFetchSite === '' && $channel !== 'api_webhook') {
            $score += 30;
            $flags[] = 'Missing modern browser Sec-Fetch-Site metadata header';
        } elseif ($secFetchSite === 'cross-site' && $channel !== 'api_webhook') {
            $score += 45;
            $flags[] = 'Unexpected cross-site form submission (Sec-Fetch-Site: cross-site)';
        }

        if ($xff !== '') {
            if (substr_count($xff, ',') >= 3 || preg_match('/(127\\.0\\.0\\.1|localhost|10\\.0\\.0\\.)/i', $xff)) {
                $score += 55;
                $flags[] = 'Suspicious X-Forwarded-For header spoofing chain';
            }
        }

        return min(100, $score);
    }

    /**
     * Calculates Shannon Entropy H(X) in bits per symbol
     */
    public function shannonEntropy(string $input): float
    {
        $str = trim($input);
        $len = strlen($str);
        if ($len === 0) {
            return 0.0;
        }
        $entropy = 0.0;
        foreach (count_chars($str, 1) as $freq) {
            $p = $freq / $len;
            $entropy -= $p * log($p, 2);
        }
        return round($entropy, 2);
    }

    /**
     * Detects QWERTY row mashing and unnatural consonant runs
     */
    private function isKeyboardMashOrGibberish(string $input): bool
    {
        $alpha = preg_replace('/[^a-zA-Z]/', '', strtolower($input)) ?? '';
        if (strlen($alpha) < 6) {
            return false;
        }
        if (preg_match('/(asdf|sdfg|dfgh|fghj|ghjk|hjkl|qwer|wert|zxcv|xcvb|[bcdfghjklmnpqrstvwxz]{6,})/i', $alpha)) {
            return true;
        }
        $vowels = preg_match_all('/[aeiouy]/', $alpha);
        $ratio  = $vowels / strlen($alpha);
        return (strlen($alpha) >= 10 && ($ratio < 0.13 || $ratio > 0.78));
    }

    /**
     * UK GDPR Pseudonymisation of Client IP Address
     */
    public function pseudonymiseIp(string $ip): string
    {
        $parts = explode('.', $ip);
        $subnet = count($parts) === 4 ? "{$parts[0]}.{$parts[1]}.{$parts[2]}.0/24" : 'ipv6::/48';
        $hmac = substr(hash_hmac('sha256', $ip, $this->dailyHmacSalt), 0, 12);

        return "{$subnet} [hmac:{$hmac}]";
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        $mask = -1 << (32 - (int) $bits);
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Dispatches an immediate UK GDPR-compliant Critical Risk email notification
     * when a screened request reaches or exceeds CRITICAL_RISK_THRESHOLD.
     */
    private function dispatchCriticalRiskAlert(
        string $auditId,
        string $channel,
        string $verdict,
        int $score,
        string $pseudoIp,
        string $senderEmail,
        array $flags
    ): bool {
        $recipient = filter_var(self::ALERT_EMAIL_ADDRESS, FILTER_VALIDATE_EMAIL);
        if ($recipient === false) {
            return false;
        }

        $safeChannel = preg_replace('/[^a-zA-Z0-9_-]/', '', $channel);
        $subject = sprintf(
            '[AegisPHP CRITICAL RISK %d/100] %s Blocked on %s (%s)',
            $score,
            $auditId,
            $safeChannel,
            $this->organizationName
        );

        $domainOnly = str_contains($senderEmail, '@')
            ? substr(strrchr($senderEmail, '@') ?: '', 1)
            : 'malformed-or-redacted';

        $flagLines = count($flags) > 0
            ? " - " . implode("\n - ", $flags)
            : " - Composite threshold exceeded";

        $body = implode("\n", [
            "CRITICAL SECURITY THRESHOLD TRIGGERED — AEGISPHP DEFENSE (BURUOPS)",
            "==================================================================",
            "Controller       : {$this->organizationName} (ICO Reg: {$this->icoRegNumber})",
            "Audit Reference  : {$auditId}",
            "Timestamp (UTC)  : " . gmdate('Y-m-d\TH:i:s\Z'),
            "Protected Channel: {$safeChannel}",
            "Verdict & Score  : {$verdict} ({$score}/100 — Critical Threshold: " . self::CRITICAL_RISK_THRESHOLD . ")",
            "Pseudonymised IP : {$pseudoIp} (UK GDPR Art. 6(1)(f) Pseudonymised)",
            "Sender Domain    : {$domainOnly}",
            "",
            "Matched Threat Heuristics:",
            $flagLines,
            "",
            "This automated alert was generated under UK GDPR Art. 6(1)(f) (Recital 49 Network & Information Security).",
            "Powered by BuruOps AegisPHP (https://github.com/buruops/aegis-php)",
        ]);

        $headers = [
            'From: AegisPHP Security Monitor <' . $this->dpoContact . '>',
            'Reply-To: ' . $this->dpoContact,
            'X-Mailer: AegisPHP-UK-Defense/8.1 (BuruOps)',
            'X-Priority: 1 (Highest)',
            'X-Aegis-Audit-ID: ' . $auditId,
            'Content-Type: text/plain; charset=UTF-8',
        ];

        return @mail($recipient, $subject, $body, implode("\r\n", $headers));
    }

    /**
     * Records pseudonymised security event with automatic UK GDPR retention pruning
     */
    private function recordProtectiveAuditLog(
        string $auditId,
        string $channel,
        string $verdict,
        int $score,
        string $pseudoIp,
        string $email,
        array $flags,
        bool $criticalAlertSent = false
    ): void {
        if ($this->pdo === null) {
            return;
        }

        // Automatically prune records older than configured UK GDPR retention period
        $this->pdo->prepare('DELETE FROM aegis_security_logs WHERE expires_at < CURRENT_TIMESTAMP')->execute();

        $stmt = $this->pdo->prepare(
            'INSERT INTO aegis_security_logs (audit_id, channel, verdict, risk_score, critical_alert_sent, pseudo_ip, email_domain, matched_flags, lawful_basis, expires_at)
             VALUES (:id, :ch, :v, :sc, :alert, :ip, :dom, :fl, :lb, datetime("now", "+' . self::LOG_RETENTION_DAYS . ' days"))'
        );
        $domain = str_contains($email, '@') ? substr(strrchr($email, '@') ?: '', 1) : 'unknown';
        $stmt->execute([
            ':id'    => $auditId,
            ':ch'    => $channel,
            ':v'     => $verdict,
            ':sc'    => $score,
            ':alert' => $criticalAlertSent ? 1 : 0,
            ':ip'    => $pseudoIp,
            ':dom'   => $domain,
            ':fl'    => json_encode($flags, JSON_THROW_ON_ERROR),
            ':lb'    => 'UK GDPR Art 6(1)(f) / PECR Reg 6 Security',
        ]);
    }
}

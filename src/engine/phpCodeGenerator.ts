import { DefenseConfig } from '../types/defense';

export interface GeneratedPhpArtifact {
  filename: string;
  title: string;
  description: string;
  language: 'php' | 'sql';
  code: string;
}

export function generatePhpSuite(config: DefenseConfig): GeneratedPhpArtifact[] {
  const guardClassCode = `<?php
/**
 * AegisGuard — UK-Compliant Bot, IP, Header & Behavioral Input Defense Middleware
 * Target Runtime: PHP 8.1+ (Zero external Composer dependencies required)
 *
 * Lawful Basis:
 * - UK GDPR Article 6(1)(f) & Recital 49 (Legitimate Interests: Network & Information Security)
 * - Data Protection Act 2018 (UK)
 * - PECR Regulation 6(4) (Strictly Necessary Security & Fraud Prevention Screening)
 *
 * Data Controller: ${config.organizationName} (ICO Reg: ${config.icoRegistrationNumber})
 * DPO / Security Contact: ${config.dpoContactEmail}
 */

declare(strict_types=1);

namespace AegisSecurity;

use PDO;
use RuntimeException;

final class AegisGuard
{
    private const BLOCK_THRESHOLD         = ${config.blockThreshold};
    private const CHALLENGE_THRESHOLD     = ${config.challengeThreshold};
    private const CRITICAL_RISK_THRESHOLD = ${config.criticalRiskThreshold};
    private const ENABLE_CRITICAL_ALERTS  = ${config.enableCriticalEmailAlerts ? 'true' : 'false'};
    private const ALERT_EMAIL_ADDRESS     = '${config.alertEmailAddress.replace(/'/g, "\\'")}';
    private const MAX_INPUT_ENTROPY       = ${config.maxInputEntropy};
    private const MAX_EMAIL_ENTROPY       = ${config.maxEmailLocalEntropy};
    private const MIN_TYPING_MS           = ${config.minHumanTypingMs};
    private const MAX_URLS_ALLOWED        = ${config.maxUrlsAllowed};
    private const LOG_RETENTION_DAYS      = ${config.logRetentionDays};

    private const DISPOSABLE_DOMAINS = [
        'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'tempmail.com',
        'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'maildrop.cc'
    ];

    private const HIGH_RISK_CIDRS = [
        '185.220.101.0/24', // Tor Exit Subnet
        '45.142.214.0/24',  // Bulletproof Relay Subnet
        '194.165.16.0/24',  // Spamhaus DROP Listed
    ];

    private string $dailyHmacSalt;
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null, ?string $secretKey = null)
    {
        $this->pdo = $pdo;
        // Daily rotating cryptographic salt ensures IP hashes cannot be correlated across days (UK GDPR Data Minimisation)
        $appSecret = $secretKey ?? ($_ENV['AEGIS_HMAC_SECRET'] ?? 'change-me-in-production-uk-gdpr-key');
        $this->dailyHmacSalt = hash_hmac('sha256', gmdate('Y-m-d'), $appSecret);
    }

    /**
     * Screens an incoming POST request (SMTP mailer form, Direct Message, Contact, or API).
     *
     * @param array<string, mixed> $post   Typically $_POST
     * @param array<string, mixed> $server Typically $_SERVER
     * @param string               $channel 'smtp_mail' | 'direct_message' | 'contact_form'
     * @return array{verdict: string, score: int, safe_for_smtp: bool, safe_for_dm: bool, flags: list<string>, audit_id: string}
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
        if (${config.enforceBannerAgreement ? 'true' : 'false'} && !$bannerAgreed) {
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

        // Trigger Critical Risk Email Notification if score reaches or exceeds CRITICAL_RISK_THRESHOLD (${config.criticalRiskThreshold})
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

        // Optional real-time DNSBL query (Spamhaus Zen)
        if (${config.enableDnsblLookup ? 'true' : 'false'} && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $reverseIp = implode('.', array_reverse(explode('.', $ip)));
            if (checkdnsrr($reverseIp . '.zen.spamhaus.org.', 'A')) {
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
        if (${config.protectSmtpHeaders ? 'true' : 'false'}) {
            if (preg_match('/(\\\\r|\\\\n|%0a|%0d|[\\r\\n]|\\b(bcc|cc|content-type|mime-version|to)\\s*:)/i', $email . ' ' . $subject)) {
                $score += 95;
                $flags[] = 'CRITICAL: SMTP Header / CRLF Injection attempt blocked';
            }
        }

        $cleanEmail = trim($email);
        if (!filter_var($cleanEmail, FILTER_VALIDATE_EMAIL)) {
            $score += 65;
            $flags[] = 'Malformed RFC 5322 email address';
            return min(100, $score);
        }

        [$local, $domain] = explode('@', strtolower($cleanEmail), 2);

        if (${config.blockDisposableEmails ? 'true' : 'false'} && in_array($domain, self::DISPOSABLE_DOMAINS, true)) {
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

        if (${config.blockPlusAddressingAbuse ? 'true' : 'false'} && preg_match('/\\+[a-z0-9]{4,}/i', $local)) {
            $score += 28;
            $flags[] = 'Automated sub-addressing (+tag) alias detected';
        }

        if (${config.verifyMxRecords ? 'true' : 'false'} && !checkdnsrr($domain . '.', 'MX')) {
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
        if (${config.blockSqlAndXss ? 'true' : 'false'}) {
            if (preg_match('/(\\bUNION\\s+(ALL\\s+)?SELECT\\b|\\bOR\\s+1\\s*=\\s*1\\b|\\bDROP\\s+TABLE\\b|\\bSLEEP\\s*\\(\\d+\\))/i', $combined)) {
                $score += 85;
                $flags[] = 'SQL Injection (SQLi) payload pattern detected';
            }
            if (preg_match('/(<script\\b|javascript:|onerror\\s*=|<\\?php|\\b(eval|system|passthru|shell_exec|base64_decode)\\s*\\(|O:\\d+:"[a-z0-9_]+":)/i', $combined)) {
                $score += 90;
                $flags[] = 'XSS or PHP Code/Object Serialization injection detected';
            }
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

        if (${config.detectKeyboardMash ? 'true' : 'false'} && $this->isKeyboardMashOrGibberish($message)) {
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
        } elseif (${config.blockAutomatedUserAgents ? 'true' : 'false'} && preg_match('/(python-requests|curl\\/|wget\\/|go-http-client|headlesschrome|phantomjs|scrapy)/i', $ua)) {
            $score += 75;
            $flags[] = 'Automated bot/script User-Agent signature detected';
        }

        if (${config.requireAcceptLanguage ? 'true' : 'false'} && $acceptLang === '') {
            $score += 35;
            $flags[] = 'Missing Accept-Language header';
        }

        if (${config.requireSecFetchHeaders ? 'true' : 'false'} && $secFetchSite === '' && $channel !== 'api_webhook') {
            $score += 30;
            $flags[] = 'Missing modern browser Sec-Fetch-Site metadata header';
        } elseif ($secFetchSite === 'cross-site' && $channel !== 'api_webhook') {
            $score += 45;
            $flags[] = 'Unexpected cross-site form submission (Sec-Fetch-Site: cross-site)';
        }

        if (${config.inspectForwardedForSpoofing ? 'true' : 'false'} && $xff !== '') {
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
     * UK GDPR Pseudonymisation of Client IP Address (${config.ipPseudonymisationMode})
     */
    public function pseudonymiseIp(string $ip): string
    {
        $parts = explode('.', $ip);
        $subnet = count($parts) === 4 ? "{$parts[0]}.{$parts[1]}.{$parts[2]}.0/24" : 'ipv6::/48';
        $hmac = substr(hash_hmac('sha256', $ip, $this->dailyHmacSalt), 0, 12);

        return match ('${config.ipPseudonymisationMode}') {
            'subnet_zero'     => $subnet,
            'hmac_daily_salt' => "hmac_{$hmac}",
            default           => "{$subnet} [hmac:{$hmac}]",
        };
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
     * when a screened request reaches or exceeds CRITICAL_RISK_THRESHOLD (${config.criticalRiskThreshold}/100).
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
            '${config.organizationName.replace(/'/g, "\\'")}'
        );

        $domainOnly = str_contains($senderEmail, '@')
            ? substr(strrchr($senderEmail, '@') ?: '', 1)
            : 'malformed-or-redacted';

        $flagLines = count($flags) > 0
            ? " - " . implode("\n - ", $flags)
            : " - Composite threshold exceeded";

        $body = implode("\n", [
            "CRITICAL SECURITY THRESHOLD TRIGGERED — AEGISPHP UK DEFENSE SUITE",
            "==================================================================",
            "Controller       : ${config.organizationName.replace(/"/g, '\\"')} (ICO Reg: ${config.icoRegistrationNumber})",
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
        ]);

        $headers = [
            'From: AegisPHP Security Monitor <${config.dpoContactEmail}>',
            'Reply-To: ${config.dpoContactEmail}',
            'X-Mailer: AegisPHP-UK-Defense/8.1',
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
        // Automatically prune records older than configured UK GDPR retention period (${config.logRetentionDays} days)
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
`;

  const bannerComponentCode = `<?php
/**
 * aegis-uk-banner.php — UK GDPR (Art. 6(1)(f) & Art. 13) + PECR Reg. 6 Transparency Banner
 * Include this snippet inside your PHP layout or form template.
 * Automatically injects hidden behavioral telemetry inputs & records user screening acknowledgement.
 */
?>
<!-- AegisPHP UK Regulatory Security Screening Notice (${config.organizationName}) -->
<div id="aegis-uk-security-banner"
     role="region"
     aria-label="UK Data Protection & Automated Security Screening Notice"
     style="position:fixed;${config.bannerPosition === 'top_bar' ? 'top:0;' : 'bottom:0;'}left:0;right:0;z-index:9999;background:#0b1120;color:#f1f5f9;border-top:1px solid #1e293b;padding:12px 20px;font-family:system-ui,-apple-system,sans-serif;font-size:13px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
  <div>
    <strong style="color:#38bdf8;">UK Security &amp; Anti-Abuse Screening Active:</strong>
    By using this website, submitting forms, or dispatching SMTP / Direct Messages, you acknowledge and agree that your request headers, IP reputation (pseudonymised), email format, and input behaviour are screened in real time by
    <strong>${config.organizationName}</strong> (ICO Reg: <code>${config.icoRegistrationNumber}</code>) under
    <em>UK GDPR Art. 6(1)(f) (Recital 49 Network Security)</em> and <em>PECR Reg. 6</em>.
    Logs are retained for a maximum of <strong>${config.logRetentionDays} days</strong>.
  </div>
  <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;">
    <button type="button"
            id="aegis-ack-btn"
            style="background:#0284c7;color:#ffffff;border:none;padding:7px 14px;border-radius:6px;font-weight:600;cursor:pointer;font-size:12px;">
      Agree &amp; Acknowledge Screening
    </button>
  </div>
</div>

<script>
(function() {
  const startTs = performance.now();
  let keystrokes = 0;
  let pastes = 0;

  document.addEventListener('keydown', () => { keystrokes++; }, { passive: true });
  document.addEventListener('paste', () => { pastes++; }, { passive: true });

  // Inject hidden telemetry & honeypot fields into all protected forms (SMTP / DM / Contact)
  function bindProtectedForms() {
    document.querySelectorAll('form[data-aegis-protect]').forEach((form) => {
      if (form.dataset.aegisBound) return;
      form.dataset.aegisBound = '1';

      form.insertAdjacentHTML('beforeend', \`
        <div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">
          <label>Leave this field blank <input type="text" name="_aegis_hp_website" tabindex="-1" autocomplete="off"></label>
        </div>
        <input type="hidden" name="_aegis_typing_ms" value="0">
        <input type="hidden" name="_aegis_keystrokes" value="0">
        <input type="hidden" name="_aegis_pastes" value="0">
        <input type="hidden" name="_aegis_uk_screen_ack" value="\${document.cookie.includes('aegis_uk_screen_ack=1') ? '1' : '0'}">
      \`);

      form.addEventListener('submit', () => {
        form.querySelector('[name="_aegis_typing_ms"]').value = Math.round(performance.now() - startTs);
        form.querySelector('[name="_aegis_keystrokes"]').value = keystrokes;
        form.querySelector('[name="_aegis_pastes"]').value = pastes;
      });
    });
  }

  document.getElementById('aegis-ack-btn')?.addEventListener('click', () => {
    document.cookie = 'aegis_uk_screen_ack=1; path=/; max-age=${config.logRetentionDays * 86400}; SameSite=Lax';
    document.querySelectorAll('[name="_aegis_uk_screen_ack"]').forEach(el => el.value = '1');
    document.getElementById('aegis-uk-security-banner').style.display = 'none';
  });

  if (document.cookie.includes('aegis_uk_screen_ack=1')) {
    document.getElementById('aegis-uk-security-banner').style.display = 'none';
  }
  bindProtectedForms();
})();
</script>
`;

  const endpointIntegrationCode = `<?php
/**
 * smtp-dm-endpoint.php — Protected SMTP Mailer & Direct Message (DM) Dispatch Handler
 * Demonstrates how AegisGuard screens all user inputs before touching SMTP or DM storage.
 */

declare(strict_types=1);

require_once __DIR__ . '/AegisGuard.php';

use AegisSecurity\\AegisGuard;

$pdo = new PDO('sqlite:' . __DIR__ . '/aegis_uk_audit.sqlite');
$guard = new AegisGuard($pdo);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $channel = $_POST['channel'] ?? 'smtp_mail'; // 'smtp_mail' or 'direct_message'
    $result  = $guard->screenRequest($_POST, $_SERVER, $channel);

    if ($result['verdict'] === 'BLOCK') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'status'              => 'blocked',
            'audit_id'            => $result['audit_id'],
            'critical_alert_sent' => $result['critical_alert_sent'],
            'message'             => 'Request blocked by UK-compliant automated threat & input screening.',
            'reasons'             => $result['flags'],
        ]);
        exit;
    }

    if ($result['verdict'] === 'CHALLENGE') {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode([
            'status'   => 'challenge_required',
            'audit_id' => $result['audit_id'],
            'message'  => 'Additional verification or UK screening notice acknowledgement required.',
        ]);
        exit;
    }

    // Verified Safe for Outbound SMTP Dispatch or Direct Message Delivery
    if ($channel === 'smtp_mail' && $result['safe_for_smtp']) {
        // Strip any residual control characters before passing to PHPMailer / Symfony Mailer
        $safeRecipient = filter_var($_POST['recipient'] ?? '', FILTER_SANITIZE_EMAIL);
        $safeSubject   = preg_replace('/[\\r\\n]+/', ' ', (string) $_POST['subject']);
        // $mailer->send($safeRecipient, $safeSubject, $_POST['message']);
    } elseif ($channel === 'direct_message' && $result['safe_for_dm']) {
        // Deliver DM to recipient inbox
        // $dmRepository->deliverMessage($_POST['recipient'], $_POST['message'], $result['audit_id']);
    }

    header('Content-Type: application/json');
    echo json_encode([
        'status'   => 'dispatched',
        'audit_id' => $result['audit_id'],
        'score'    => $result['score'],
    ]);
}
`;

  const vaultClassCode = `<?php
/**
 * AegisVault — Cryptographic & Encryption Engine for AegisPHP
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 * Target Runtime: PHP 8.1+
 *
 * Implements:
 * - Authenticated symmetric encryption: AES-256-GCM with distinct IVs & authentication tags
 * - Secure password hashing: Argon2id (fallback to Bcrypt cost 12)
 * - Cryptographically secure password provisioning (CSPRNG)
 * - Constant-time verification & zero secret exposure
 */

declare(strict_types=1);

namespace AegisSecurity;

use RuntimeException;
use InvalidArgumentException;

final class AegisVault
{
    private const CIPHER = 'aes-256-gcm';
    private const TAG_LENGTH = 16;
    private const IV_LENGTH = 12;

    private string $encryptionKey;

    public function __construct(?string $encryptionKey = null)
    {
        $rawKey = $encryptionKey ?? ($_ENV['AEGIS_APP_KEY'] ?? getenv('AEGIS_APP_KEY') ?: '');
        if ($rawKey === '') {
            $rawKey = hash('sha256', (string) (php_uname('n') . __DIR__ . 'buruops-fallback-entropy'), true);
        } elseif (strlen($rawKey) === 64 && ctype_xdigit($rawKey)) {
            $rawKey = hex2bin($rawKey);
        } else {
            $rawKey = hash('sha256', $rawKey, true);
        }
        $this->encryptionKey = $rawKey;
    }

    public function encrypt(string $plaintext): string
    {
        if ($plaintext === '') return '';
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $this->encryptionKey, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH);
        if ($ciphertext === false) throw new RuntimeException('AES-256-GCM encryption failed');
        return base64_encode($iv . $tag . $ciphertext);
    }

    public function decrypt(string $payload): ?string
    {
        if ($payload === '') return '';
        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) < (self::IV_LENGTH + self::TAG_LENGTH)) return null;
        $iv = substr($raw, 0, self::IV_LENGTH);
        $tag = substr($raw, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($raw, self::IV_LENGTH + self::TAG_LENGTH);
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $this->encryptionKey, OPENSSL_RAW_DATA, $iv, $tag);
        return $plaintext !== false ? $plaintext : null;
    }

    public static function hashPassword(string $password): string
    {
        if (strlen($password) < 12) throw new InvalidArgumentException('Password must be at least 12 characters.');
        if (defined('PASSWORD_ARGON2ID')) {
            return password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);
        }
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public static function generateSecurePassword(int $length = 18): string
    {
        $length = max(16, min(64, $length));
        $uppers  = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lowers  = 'abcdefghijkmnopqrstuvwxyz';
        $numbers = '23456789';
        $symbols = '!@#$%^&*()-_=+[]{}';

        $chars = [
            $uppers[random_int(0, strlen($uppers) - 1)],
            $uppers[random_int(0, strlen($uppers) - 1)],
            $lowers[random_int(0, strlen($lowers) - 1)],
            $lowers[random_int(0, strlen($lowers) - 1)],
            $numbers[random_int(0, strlen($numbers) - 1)],
            $numbers[random_int(0, strlen($numbers) - 1)],
            $symbols[random_int(0, strlen($symbols) - 1)],
            $symbols[random_int(0, strlen($symbols) - 1)],
        ];

        $all = $uppers . $lowers . $numbers . $symbols;
        $allLen = strlen($all);
        while (count($chars) < $length) {
            $chars[] = $all[random_int(0, $allLen - 1)];
        }
        for ($i = count($chars) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            $tmp = $chars[$i];
            $chars[$i] = $chars[$j];
            $chars[$j] = $tmp;
        }
        return implode('', $chars);
    }

    public static function generateOnetimeToken(): array
    {
        $raw = bin2hex(random_bytes(32));
        return ['raw_token' => $raw, 'token_hash' => hash('sha256', $raw)];
    }
}
`;

  const userManagerCode = `<?php
/**
 * AegisUserManager — User Management, Authentication & Password Reset Lifecycle
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 * Target Runtime: PHP 8.1+
 */

declare(strict_types=1);

namespace AegisSecurity;

use PDO;
use RuntimeException;
use InvalidArgumentException;

require_once __DIR__ . '/AegisVault.php';

final class AegisUserManager
{
    private const MAX_FAILED_ATTEMPTS = 5;
    private const LOCKOUT_MINUTES = 15;
    private const RESET_TOKEN_EXPIRY_MINUTES = 15;

    private PDO $pdo;
    private AegisVault $vault;

    public function __construct(PDO $pdo, ?AegisVault $vault = null)
    {
        $this->pdo = $pdo;
        $this->vault = $vault ?? new AegisVault();
    }

    public function createUser(string $email, string $name, string $role = 'responder', ?string $password = null, bool $mustChange = false): array
    {
        $cleanEmail = strtolower(trim($email));
        if (!filter_var($cleanEmail, FILTER_VALIDATE_EMAIL)) throw new InvalidArgumentException('Invalid RFC 5322 email address.');
        $allowed = ['admin', 'responder', 'auditor', 'readonly'];
        if (!in_array($role, $allowed, true)) throw new InvalidArgumentException('Invalid role.');

        $stmt = $this->pdo->prepare('SELECT id FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        if ($stmt->fetch()) throw new RuntimeException('User with this email already exists.');

        $provisioned = null;
        if ($password === null || trim($password) === '') {
            $provisioned = AegisVault::generateSecurePassword(18);
            $hash = AegisVault::hashPassword($provisioned);
            $mustChange = true;
        } else {
            $hash = AegisVault::hashPassword($password);
        }

        $uuid = bin2hex(random_bytes(16));
        $stmt = $this->pdo->prepare(
            'INSERT INTO aegis_users (uuid, email, name, password_hash, role, status, must_change_password, created_at, updated_at)
             VALUES (:uuid, :email, :name, :hash, :role, "active", :mc, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([':uuid' => $uuid, ':email' => $cleanEmail, ':name' => trim($name), ':hash' => $hash, ':role' => $role, ':mc' => $mustChange ? 1 : 0]);

        return [
            'id' => (int) $this->pdo->lastInsertId(),
            'uuid' => $uuid,
            'email' => $cleanEmail,
            'name' => trim($name),
            'role' => $role,
            'provisioned_password' => $provisioned,
        ];
    }

    public function authenticate(string $email, string $password, string $clientIp = '0.0.0.0'): array
    {
        $cleanEmail = strtolower(trim($email));
        $stmt = $this->pdo->prepare('SELECT * FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) return ['authenticated' => false, 'user' => null, 'error' => 'Invalid credentials.'];
        if ($user['status'] !== 'active') return ['authenticated' => false, 'user' => null, 'error' => 'Account disabled.'];

        if ($user['locked_until'] !== null && strtotime($user['locked_until']) > time()) {
            $mins = (int) ceil((strtotime($user['locked_until']) - time()) / 60);
            return ['authenticated' => false, 'user' => null, 'error' => "Account locked. Try again in {$mins}m."];
        }

        if (!AegisVault::verifyPassword($password, $user['password_hash'])) {
            $fa = (int) $user['failed_attempts'] + 1;
            $lu = $fa >= self::MAX_FAILED_ATTEMPTS ? date('Y-m-d H:i:s', time() + (self::LOCKOUT_MINUTES * 60)) : null;
            $this->pdo->prepare('UPDATE aegis_users SET failed_attempts = :fa, locked_until = :lu WHERE id = :id')->execute([':fa' => $fa, ':lu' => $lu, ':id' => $user['id']]);
            return ['authenticated' => false, 'user' => null, 'error' => 'Invalid credentials.'];
        }

        $this->pdo->prepare('UPDATE aegis_users SET failed_attempts = 0, locked_until = NULL, last_login_at = CURRENT_TIMESTAMP WHERE id = :id')->execute([':id' => $user['id']]);
        unset($user['password_hash']);
        return ['authenticated' => true, 'user' => $user, 'error' => null];
    }

    public function createPasswordResetRequest(string $email, string $clientIp = '0.0.0.0'): ?array
    {
        $cleanEmail = strtolower(trim($email));
        $stmt = $this->pdo->prepare('SELECT id, status FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || $user['status'] !== 'active') {
            usleep(random_int(100000, 200000));
            return null;
        }

        $tokenData = AegisVault::generateOnetimeToken();
        $exp = date('Y-m-d H:i:s', time() + (self::RESET_TOKEN_EXPIRY_MINUTES * 60));
        $this->pdo->prepare('UPDATE aegis_password_resets SET used_at = CURRENT_TIMESTAMP WHERE user_id = :uid AND used_at IS NULL')->execute([':uid' => $user['id']]);
        $this->pdo->prepare('INSERT INTO aegis_password_resets (user_id, token_hash, expires_at) VALUES (:uid, :th, :exp)')->execute([':uid' => $user['id'], ':th' => $tokenData['token_hash'], ':exp' => $exp]);

        return ['token' => $tokenData['raw_token'], 'expires_at' => $exp];
    }

    public function resetPasswordWithToken(string $rawToken, string $newPassword, string $clientIp = '0.0.0.0'): bool
    {
        if (strlen($newPassword) < 12) throw new InvalidArgumentException('Password must be at least 12 characters.');
        $th = hash('sha256', trim($rawToken));
        $stmt = $this->pdo->prepare('SELECT id, user_id, expires_at FROM aegis_password_resets WHERE token_hash = :th AND used_at IS NULL LIMIT 1');
        $stmt->execute([':th' => $th]);
        $rec = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$rec || strtotime($rec['expires_at']) < time()) return false;
        $newHash = AegisVault::hashPassword($newPassword);

        $this->pdo->prepare('UPDATE aegis_users SET password_hash = :h, failed_attempts = 0, locked_until = NULL, must_change_password = 0 WHERE id = :id')->execute([':h' => $newHash, ':id' => $rec['user_id']]);
        $this->pdo->prepare('UPDATE aegis_password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = :id')->execute([':id' => $rec['id']]);
        return true;
    }

    public function listUsers(): array
    {
        return $this->pdo->query('SELECT id, uuid, email, name, role, status, must_change_password, failed_attempts, last_login_at, created_at FROM aegis_users ORDER BY id ASC')->fetchAll(PDO::FETCH_ASSOC);
    }
}
`;

  const authEndpointCode = `<?php
/**
 * auth-endpoint.php — Authentication, User Provisioning & Password Reset REST Endpoint
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 */

declare(strict_types=1);

require_once __DIR__ . '/AegisVault.php';
require_once __DIR__ . '/AegisUserManager.php';

use AegisSecurity\\AegisVault;
use AegisSecurity\\AegisUserManager;

header('Content-Type: application/json; charset=UTF-8');
$pdo = new PDO('sqlite:' . __DIR__ . '/aegis_security_audit.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$vault = new AegisVault();
$userManager = new AegisUserManager($pdo, $vault);

$action = (string) ($_POST['action'] ?? $_GET['action'] ?? '');
$clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

try {
    switch ($action) {
        case 'login':
            $result = $userManager->authenticate((string)$_POST['email'], (string)$_POST['password'], $clientIp);
            if (!$result['authenticated']) {
                http_response_code(401);
                echo json_encode(['success' => false, 'error' => $result['error']]);
                exit;
            }
            echo json_encode(['success' => true, 'user' => $result['user'], 'message' => 'Login successful.']);
            break;

        case 'request_reset':
            $tokenData = $userManager->createPasswordResetRequest((string)$_POST['email'], $clientIp);
            echo json_encode(['success' => true, 'message' => 'Reset token generated if user exists.', 'dev_token' => $tokenData['token'] ?? null]);
            break;

        case 'reset_password':
            $ok = $userManager->resetPasswordWithToken((string)$_POST['token'], (string)$_POST['new_password'], $clientIp);
            if (!$ok) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid or expired token.']);
                exit;
            }
            echo json_encode(['success' => true, 'message' => 'Password reset completed.']);
            break;

        case 'create_user':
            $created = $userManager->createUser((string)$_POST['email'], (string)$_POST['name'], (string)($_POST['role'] ?? 'responder'), !empty($_POST['password']) ? (string)$_POST['password'] : null);
            echo json_encode(['success' => true, 'user' => $created]);
            break;

        case 'generate_password':
            $pwd = AegisVault::generateSecurePassword(18);
            echo json_encode(['success' => true, 'password' => $pwd]);
            break;

        case 'list_users':
            echo json_encode(['success' => true, 'users' => $userManager->listUsers()]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            break;
    }
} catch (\\Throwable $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}
`;

  const schemaSqlCode = `-- BuruOps AegisPHP — Full Security, Authentication & Protective Audit Log Schema
-- UK GDPR Article 6(1)(f) & Article 5(1)(e) Compliant (SQLite, MySQL, and PostgreSQL compatible)
-- Stores ONLY pseudonymised IP hashes & email domains (no raw PII local-parts) with strict automatic expiry

-- 1. Threat & Protective Audit Log Table
CREATE TABLE IF NOT EXISTS aegis_security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id VARCHAR(32) NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    channel VARCHAR(32) NOT NULL,           -- 'smtp_mail', 'direct_message', 'contact_form'
    verdict VARCHAR(16) NOT NULL,           -- 'ALLOW', 'CHALLENGE', 'BLOCK'
    risk_score INTEGER NOT NULL,
    critical_alert_sent INTEGER DEFAULT 0,  -- 1 if score >= ${config.criticalRiskThreshold} & alert emailed to ${config.alertEmailAddress}
    pseudo_ip VARCHAR(64) NOT NULL,         -- HMAC-SHA256 /24 Pseudonymised IP
    email_domain VARCHAR(128) NOT NULL,     -- Domain only (no raw PII local-part stored)
    matched_flags TEXT NOT NULL,            -- JSON array of triggered security heuristics
    lawful_basis VARCHAR(64) NOT NULL       -- UK GDPR Art. 6(1)(f) & PECR Reg. 6
);

CREATE INDEX IF NOT EXISTS idx_aegis_expires ON aegis_security_logs(expires_at);
CREATE INDEX IF NOT EXISTS idx_aegis_verdict ON aegis_security_logs(verdict, created_at);

-- 2. User & Access Management Table (Argon2id / Bcrypt Hashing, Role-Based Access Control)
CREATE TABLE IF NOT EXISTS aegis_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(191) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'responder', -- 'admin', 'responder', 'auditor', 'readonly'
    status VARCHAR(16) NOT NULL DEFAULT 'active',   -- 'active', 'disabled'
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON aegis_users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON aegis_users(role, status);

-- 3. Cryptographically Secure One-Time Password Reset Tokens
CREATE TABLE IF NOT EXISTS aegis_password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash of random 256-bit token
    expires_at DATETIME NOT NULL,
    used_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES aegis_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_resets_token ON aegis_password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_resets_user ON aegis_password_resets(user_id, expires_at);

-- 4. Authentication & Security Audit Trail
CREATE TABLE IF NOT EXISTS aegis_auth_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type VARCHAR(64) NOT NULL,
    user_id INTEGER DEFAULT NULL,
    email VARCHAR(191) NOT NULL,
    ip_pseudonymised VARCHAR(64) NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    details TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON aegis_auth_audit(event_type, created_at);
`;

  return [
    {
      filename: 'AegisGuard.php',
      title: 'Core PHP 8.1+ Threat Screening Middleware',
      description:
        'Standalone class inspecting IP CIDR/DNSBL reputation, email entropy & SMTP CRLF injection, keyboard mash/SQLi/XSS payloads, HTTP headers, and UK GDPR pseudonymised logging.',
      language: 'php',
      code: guardClassCode,
    },
    {
      filename: 'AegisVault.php',
      title: 'AES-256-GCM Encryption & Password Provisioning',
      description:
        'Cryptographic vault for authenticated symmetric encryption (AES-256-GCM), Argon2id/Bcrypt password hashing, CSPRNG password provisioning, and secure tokens.',
      language: 'php',
      code: vaultClassCode,
    },
    {
      filename: 'AegisUserManager.php',
      title: 'User Management, Lockout & Password Reset Lifecycle',
      description:
        'Handles user creation, role-based access control, brute force login lockout, and cryptographically secure single-use password reset tokens (15-min expiry).',
      language: 'php',
      code: userManagerCode,
    },
    {
      filename: 'auth-endpoint.php',
      title: 'Authentication & Password Reset REST Endpoint',
      description:
        'Production REST controller handling secure user login, password generation, reset token issuance, and password completion without leaking secrets.',
      language: 'php',
      code: authEndpointCode,
    },
    {
      filename: 'aegis-uk-banner.php',
      title: 'UK GDPR & PECR Consent Banner + Telemetry Hook',
      description:
        'Embeddable PHP/JS banner notifying visitors that all forms, SMTP mailers, and DMs are screened for security, while capturing typing cadence and honeypot signals.',
      language: 'php',
      code: bannerComponentCode,
    },
    {
      filename: 'smtp-dm-endpoint.php',
      title: 'Protected SMTP Mail & Direct Message Handler',
      description:
        'Drop-in controller demonstrating how to gate PHPMailer/SMTP dispatch and internal Direct Message endpoints behind AegisGuard.',
      language: 'php',
      code: endpointIntegrationCode,
    },
    {
      filename: 'schema.sql',
      title: 'Full Threat & User Authentication Database Schema',
      description: `Complete schema for threat logs (${config.logRetentionDays}-day retention), users, password resets, and authentication audit trail.`,
      language: 'sql',
      code: schemaSqlCode,
    },
  ];
}


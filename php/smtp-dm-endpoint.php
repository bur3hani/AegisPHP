<?php
/**
 * smtp-dm-endpoint.php — Example Protected Endpoint (SMTP Mailer & Direct Message)
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 *
 * Demonstrates how to gate PHPMailer, Symfony Mailer, mail(), and Direct Message channels.
 */

declare(strict_types=1);

require_once __DIR__ . '/AegisGuard.php';

use AegisSecurity\AegisGuard;

// Setup SQLite audit database (or MySQL / PostgreSQL PDO)
$dbFile = __DIR__ . '/aegis_security_audit.sqlite';
$pdo = new PDO('sqlite:' . $dbFile);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Initialise table if not already created
$pdo->exec((string) file_get_contents(__DIR__ . '/schema.sql'));

// Instantiate AegisGuard with custom organization details
$guard = new AegisGuard(
    pdo: $pdo,
    secretKey: getenv('AEGIS_HMAC_SECRET') ?: 'buruops-production-hmac-salt',
    organizationName: 'BuruOps Digital Security',
    icoRegNumber: 'ZB491820',
    dpoContact: 'secops@buruops.local'
);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $channel = (string) ($_POST['channel'] ?? 'smtp_mail'); // 'smtp_mail' | 'direct_message' | 'contact_form'

    // Screen request across all 4 defense vectors
    $result = $guard->screenRequest($_POST, $_SERVER, $channel);

    if ($result['verdict'] === 'BLOCK') {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'status'              => 'blocked',
            'audit_id'            => $result['audit_id'],
            'score'               => $result['score'],
            'critical_alert_sent' => $result['critical_alert_sent'],
            'message'             => 'Request blocked by BuruOps AegisPHP security screening.',
            'reasons'             => $result['flags'],
        ], JSON_PRETTY_PRINT);
        exit;
    }

    if ($result['verdict'] === 'CHALLENGE') {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode([
            'status'   => 'challenge_required',
            'audit_id' => $result['audit_id'],
            'score'    => $result['score'],
            'message'  => 'Suspicious patterns detected or UK regulatory screening banner agreement missing.',
            'reasons'  => $result['flags'],
        ], JSON_PRETTY_PRINT);
        exit;
    }

    // --- SAFE FOR OUTBOUND SMTP DISPATCH OR DM DELIVERY ---
    if ($channel === 'smtp_mail' && $result['safe_for_smtp']) {
        $safeRecipient = filter_var($_POST['recipient'] ?? '', FILTER_SANITIZE_EMAIL);
        // Strip any residual CRLF control characters before passing to mailer
        $safeSubject   = preg_replace('/[\r\n]+/', ' ', (string) ($_POST['subject'] ?? ''));
        $safeMessage   = (string) ($_POST['message'] ?? '');

        // Example PHPMailer / mail() execution:
        // mail($safeRecipient, $safeSubject, $safeMessage, "From: webmaster@yourdomain.co.uk");
    } elseif ($channel === 'direct_message' && $result['safe_for_dm']) {
        // Safe DM delivery logic
        $recipient = htmlspecialchars((string) ($_POST['recipient'] ?? ''), ENT_QUOTES, 'UTF-8');
        $message   = (string) ($_POST['message'] ?? '');
        // $dmService->deliver($recipient, $message, $result['audit_id']);
    }

    header('Content-Type: application/json');
    echo json_encode([
        'status'   => 'dispatched',
        'audit_id' => $result['audit_id'],
        'score'    => $result['score'],
        'message'  => 'Input passed all 4 security vectors successfully.',
    ], JSON_PRETTY_PRINT);
    exit;
}

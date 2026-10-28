# AegisPHP — Standalone PHP 8.1+ Security Library
> **A project by BuruOps** &bull; Author: **Engr. Buru** ([engr.buru@gmail.com](mailto:engr.buru@gmail.com))  
> *Licensed under the MIT License with Attribution.*

This folder contains the complete, production-ready, standalone PHP 8.1+ library with **zero external Composer dependencies required**.

---

## Files in this Directory

| File | Description |
|---|---|
| `AegisGuard.php` | The primary screening middleware class. Handles IP CIDR & DNSBL reputation, RFC 5322 email & SMTP CRLF injection filtering, Shannon entropy analysis, QWERTY keyboard mash detection, SQLi/XSS payload inspection, HTTP header integrity verification, UK GDPR HMAC-SHA256 IP pseudonymisation, and automatic protective log retention pruning. |
| `aegis-uk-banner.php` | Embeddable UK GDPR Art. 6(1)(f) & PECR Reg. 6 transparent screening notice banner. Automatically injects hidden behavioral telemetry fields (`typing_ms`, `keystrokes`, `pastes`, `honeypot`) into protected web forms. |
| `smtp-dm-endpoint.php` | Reference implementation showing how to intercept and screen submissions before triggering outbound emails via `mail()`/`PHPMailer` or saving Direct Messages to a database. |
| `schema.sql` | Database schema for storing protective audit events (SQLite, MySQL, and PostgreSQL compatible). Enforces data minimisation and storage limitation. |

---

## 3-Minute Integration Guide

### Step 1: Initialize Database Table
```bash
# SQLite example
sqlite3 aegis_security_audit.sqlite < schema.sql

# Or execute schema.sql in MySQL / MariaDB / PostgreSQL
```

### Step 2: Intercept Form / SMTP Submissions
```php
<?php
declare(strict_types=1);

require_once __DIR__ . '/AegisGuard.php';

use AegisSecurity\AegisGuard;

$pdo = new PDO('sqlite:' . __DIR__ . '/aegis_security_audit.sqlite');
$guard = new AegisGuard(
    pdo: $pdo,
    secretKey: getenv('AEGIS_HMAC_SECRET') ?: 'your-secure-daily-salt',
    organizationName: 'Your Organization Ltd',
    icoRegNumber: 'ZB123456',
    dpoContact: 'secops@yourdomain.co.uk'
);

// Screen input across all 4 defense vectors
$result = $guard->screenRequest($_POST, $_SERVER, 'smtp_mail');

if ($result['verdict'] === 'BLOCK') {
    http_response_code(403);
    echo json_encode([
        'error'    => 'Request blocked by automated threat screening.',
        'audit_id' => $result['audit_id']
    ]);
    exit;
}

// Proceed safely with PHPMailer or mail()
// mail($safeTo, $safeSubject, $safeBody);
```

### Step 3: Embed the UK Banner in Your Templates
Include before `</body>`:
```php
<?php include_once __DIR__ . '/aegis-uk-banner.php'; ?>
```

---

## Attribution Notice
This software is developed by **BuruOps**. Any use, fork, or redistribution must maintain visible attribution to **BuruOps** (Engr. Buru).

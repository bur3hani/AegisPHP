# AegisPHP — UK-Compliant Bot, IP, Header & Behavioral Input Defense Suite

> **A project by BuruOps** &bull; Created by **Engr. Buru** ([engr.buru@gmail.com](mailto:engr.buru@gmail.com))  
> *Open-source security middleware for PHP applications — free to use with attribution.*

[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-777bb4.svg?logo=php&logoColor=white)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg?logo=typescript&logoColor=white)](#)
[![Compliance](https://img.shields.io/badge/Compliance-UK%20GDPR%20%7C%20PECR%20Reg%206-0284c7.svg)](#uk-regulatory-compliance)
[![License: MIT](https://img.shields.io/badge/License-MIT%20with%20Attribution-10b981.svg)](LICENSE)

**AegisPHP** is a dual-tier cybersecurity project designed to mitigate automated botnet attacks, malicious human form tampering, credential stuffing, and spam floods targeting PHP-based web applications, outbound SMTP mailers, Direct Message (DM) channels, and public forms.

It consists of:
1. **Interactive Threat Workbench & Screener** (`/src`): A modern React 19 + TypeScript + Tailwind CSS + Recharts visual console to simulate traffic, analyze threat vectors in real time, inspect 24-hour time-series logs, test UK consent banners, and export custom-calibrated PHP middleware.
2. **Turnkey Standalone PHP 8.1+ Library** (`/php`): A zero-dependency, drop-in PHP class (`AegisGuard.php`), UK regulatory consent banner (`aegis-uk-banner.php`), sample protected SMTP/DM controller (`smtp-dm-endpoint.php`), and privacy-compliant database schema (`schema.sql`).

---

## Key Features & 4-Vector Defense Architecture

AegisPHP screens every request across four distinct vectors before any outbound email is sent via `mail()`/`PHPMailer` or stored in a database:

```
 Incoming Request (POST)
   │
   ├── Vector 1: IP Reputation & ASN Intelligence (Tor Exit Nodes, Bulletproof CIDRs, DNSBL)
   ├── Vector 2: Email Format & SMTP CRLF Injection Hygiene (\r\nBcc:, Disposable Domains)
   ├── Vector 3: Behavioral Input Telemetry (Shannon Entropy, QWERTY Mash, SQLi/XSS, Fill Speed)
   └── Vector 4: Unexpected HTTP Request Headers (Sec-Fetch-*, Accept-Language, Script Bots)
   │
   ▼
 Composite Risk Calculation (0 - 100)
   ├── ALLOW (Score < 35)      ──> Pass to PHPMailer / DM Dispatch
   ├── CHALLENGE (35 <= Score) ──> Hold / Require Banner Acknowledgement
   └── BLOCK (Score >= 65)     ──> HTTP 403 Forbidden + Pseudonymised Protective Log
         └── CRITICAL (>= 85)  ──> Instant Incident Alert Email via dispatchCriticalRiskAlert()
```

### 1. Vector 1: IP Reputation & Network Intelligence
- Screens client IP against known **Tor exit subnets** (`185.220.101.0/24`), **bulletproof relays** (`45.142.214.0/24`), and **Spamhaus DROP/ZEN DNSBLs**.
- Flags non-residential datacenter ASNs submitting public contact or Direct Message forms.
- Protects client privacy by never storing raw IP addresses (daily HMAC-SHA256 salted hash + `/24` subnet mask).

### 2. Vector 2: Email Hygiene & Outbound SMTP Protection
- **SMTP Header / CRLF Injection Mitigation**: Scans for `\r`, `\n`, `%0a`, `%0d`, `Bcc:`, `Cc:`, and `Content-Type:` manipulation attempts before inputs can compromise outbound mail servers.
- **Burner / Disposable Email Filtering**: Blocks 10-minute mail domains (`mailinator.com`, `sharklasers.com`, `tempmail.com`, etc.).
- **Shannon Entropy Analysis**: Detects machine-generated randomized local-parts (`x89a7s9d8f@gmail.com`).
- **Dot-Splitting & Plus-Addressing Evasion**: Detects Gmail dot-stuffing and automated `+tag` alias floods.

### 3. Vector 3: Behavioral Telemetry & Malicious Payloads
- **Shannon Entropy Analyzer**: Computes character entropy $H(X)$ in bits per character to flag random strings and encrypted payloads.
- **Keyboard Mashing & Gibberish Detection**: Catches physical QWERTY row mashing (`asdfjkl;`, `zxcvbnm`) and abnormal consonant runs.
- **Web Exploit Signatures**: Inspects form payloads for SQL Injection (`UNION SELECT`, `OR 1=1`), XSS `<script>`, and PHP serialized object injection (`O:8:"Exploit":`).
- **Superhuman Velocity Detection**: Flags form submissions filled under 1,400ms or submitted with 0 physical DOM keystrokes.
- **Invisible Honeypot Trap**: Invisible ARIA honeypot traps automated bots instantly.

### 4. Vector 4: Unexpected HTTP Request Headers
- Flags automated script client signatures (`python-requests`, `curl`, `Go-http-client`, `HeadlessChrome`).
- Flags missing standard browser headers (`Accept-Language`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`).
- Detects forged or spoofed `X-Forwarded-For` proxy chains.

---

## UK Regulatory Compliance (UK GDPR & PECR)

AegisPHP is architected specifically to comply with the **UK General Data Protection Regulation (UK GDPR)**, the **Data Protection Act 2018**, and the **Privacy and Electronic Communications Regulations (PECR)**:

1. **Lawful Basis — UK GDPR Article 6(1)(f) & Recital 49**:
   - Processing IP reputation and request telemetry for network and information security is explicitly recognized as an overriding legitimate interest.
2. **Right to Be Informed (Article 13) & User Agreement Banner**:
   - The interactive banner informs visitors that using the website, SMTP mailers, or DM channels constitutes agreement to automated protective screening and logging.
3. **PECR Regulation 6(4) Exemption**:
   - Security screening cookies/tokens (`aegis_uk_screen_ack`) are classified as strictly necessary for security and fraud prevention.
4. **Data Minimisation & Storage Limitation (Article 5(1)(c) & (e))**:
   - Raw IPv4/IPv6 literals are **never** written to database disk. They are transformed into pseudonymised strings using daily-rotating HMAC-SHA256 salts.
   - Built-in SQL statements automatically purge audit logs older than the configured retention period (default: 30 days).

---

## Automated Critical Risk Email Notifications

When an incoming request triggers severe threat flags and composite risk reaches or exceeds the **Critical Risk Threshold** (default: `85/100`), `AegisGuard` immediately dispatches an incident notification email:

- **Configurable Threshold**: Set sensitivity between `50` and `100`.
- **Target Recipient**: Configured via `ALERT_EMAIL_ADDRESS` (e.g., `secops-alerts@yourdomain.co.uk`).
- **RFC 5322 Compliant Email Header**: Dispatches with `X-Priority: 1 (Highest)`, `X-Aegis-Audit-ID`, and sanitized threat summary.
- **Privacy-Safe Content**: Only includes the pseudonymised IP hash, domain, and matched rule flags (no raw personal data leaked into email inboxes).

---

## Project Structure

```
├── php/                                # Standalone PHP 8.1+ Production Library
│   ├── AegisGuard.php                  # Core threat screening & rate-limiting middleware
│   ├── AegisVault.php                  # Cryptographic vault: AES-256-GCM authenticated encryption & CSPRNG
│   ├── AegisUserManager.php            # User CRUD, Argon2id auth, brute-force lockouts & reset tokens
│   ├── auth-endpoint.php               # REST API for login, user provisioning & password resets
│   ├── aegis-uk-banner.php             # UK GDPR/PECR compliance banner & JS telemetry hook
│   ├── smtp-dm-endpoint.php            # Example protected SMTP mailer & DM handler
│   └── schema.sql                      # Privacy-safe schema (threat logs, users, resets, auth audits)
├── src/                                # Interactive Workbench & Visual Console (React 19)
│   ├── types/defense.ts                # TypeScript interfaces for rules, telemetry, users & audits
│   ├── engine/threatEngine.ts          # Deterministic 4-vector evaluation engine
│   ├── engine/vaultSimulator.ts        # Client-side CSPRNG password & AES-256-GCM simulation
│   ├── engine/phpCodeGenerator.ts      # Dynamic PHP generator tailored to user config
│   ├── App.tsx                         # Multi-workspace GUI (Screener, Logs, Compliance, Users, Export)
│   ├── main.tsx                        # React application bootstrap
│   └── index.css                       # Tailwind CSS setup
├── .env.example                        # Zero-secrets environment template with CSPRNG generators
├── package.json                        # Node.js dependencies (Vite, Recharts, Lucide, Tailwind)
├── tsconfig.json                       # TypeScript compiler configuration
├── vite.config.ts                      # Vite build configuration
├── LICENSE                             # MIT License with BuruOps attribution requirement
└── README.md                           # Documentation & quick start guide
```

---

## Zero Secrets Architecture & Cryptographic Vault

AegisPHP adheres to an absolute **zero secrets exposure** policy. No plaintext passwords, database passwords, API tokens, or encryption keys are hardcoded in the codebase:

1. **Environment Separation (`.env`)**:
   - Master keys and database credentials are read exclusively from environment variables or secure key vaults.
   - Use `.env.example` as a template. Generate cryptographically secure 256-bit keys using OpenSSL:
     ```bash
     # Generate master AES-256 encryption key (32 bytes / 64 hex characters)
     openssl rand -hex 32

     # Generate daily HMAC pseudonymisation salt
     openssl rand -hex 32
     ```
2. **Authenticated Symmetric Encryption (`AegisVault.php`)**:
   - Sensitive database fields (SMTP relay passwords, alert credentials, webhooks, customer PII) are encrypted using **AES-256-GCM** (Galois/Counter Mode).
   - Every encryption operation generates a unique cryptographically secure 96-bit (12-byte) Initialization Vector (`IV`) and computes a 128-bit (16-byte) authentication tag to guarantee ciphertext integrity and authenticity prior to decryption.
3. **Argon2id Memory-Hard Password Hashing**:
   - All user passwords are automatically hashed using `PASSWORD_ARGON2ID` with high memory-hardness (`memory_cost = 65536 KiB`, `time_cost = 4`, `threads = 1`), with automatic fallback to `PASSWORD_BCRYPT` (`cost = 12`) on legacy hosts.
   - Plaintext passwords are never stored, logged, or serialized.

---

## User Management & Password Reset Lifecycle

A complete SecOps user and credential management system is integrated directly into both the PHP suite (`php/AegisUserManager.php`, `php/auth-endpoint.php`) and the interactive workbench (`Access & Users` tab):

### 1. User Provisioning & Role-Based Access Control (RBAC)
- **Roles**:
  - `admin`: Full system management, encryption key rotation, threshold overrides, and user CRUD.
  - `responder`: Incident triage, IP blocklist overrides, quarantined message reviews.
  - `auditor`: Compliance inspection, UK GDPR audit log export.
  - `readonly`: Dashboard metrics and real-time threat feed inspection.
- **Account Status**: Toggle operators between `active` and `disabled`. Disabled accounts are rejected before credential evaluation.
- **CSPRNG Password Generation**: Built-in 18-character password generator sampling across uppercase, lowercase, numbers, and symbols with Shannon entropy calculation ($> 90$ bits).

### 2. Brute-Force Rate Limiting & Account Lockout
- Accounts track failed consecutive login attempts (`failed_login_attempts`).
- **5-Attempt Lockout**: Upon 5 failed attempts, the account is automatically locked for 15 minutes (`locked_until`).
- Resetting or unlocking an account can be performed programmatically via `unlockUser($userId)` or by an authorized administrator in the dashboard.

### 3. Secure Single-Use Password Reset
- **Zero-Knowledge Token Architecture**:
  - A cryptographically random 256-bit token is generated for the user (`bin2hex(random_bytes(32))`).
  - **Critical Security Feature**: The raw token is sent to the user via out-of-band communication (email/SMS), but **only its SHA-256 hash (`hash('sha256', $rawToken)`) is stored in the database**. Even if the database is breached, the attacker cannot reverse the hash to forge an active reset link.
- **Strict Time Window**: Tokens expire automatically after 15 minutes.
- **Single-Use Invalidation**: Once consumed, the token record is immediately marked `used = 1` and deleted or invalidated.
- **Mandatory Reset Flag**: Administrators can flag accounts with `must_change_password = 1` to force users to choose a new password upon first login.

---

## How to Run the Interactive Workbench (Local GUI)

The interactive workbench allows you to test attack vectors, calibrate thresholds, visualize 24-hour time-series logs with Recharts, and customize your UK compliance banner.

### Prerequisites
- Node.js 18+ or 20+
- npm or pnpm / yarn

### Installation & Startup

```bash
# 1. Clone the repository
git clone https://github.com/buruops/aegis-php.git
cd aegis-php

# 2. Install dependencies
npm install

# 3. Start the local development server (runs on port 3000)
npm run dev
```

Open your browser at `http://localhost:3000` to access the workbench:
- **Live Screener**: Test live typing cadence, inject SQLi/XSS/SMTP CRLF payloads, or load preset attacks (Tor exit node, bulletproof host, Python botnet).
- **Protective Logs**: View real-time 24-hour Recharts time-series trends (Blocked vs. Allowed vs. Challenged) and inspect individual forensic records.
- **UK Compliance**: Configure your ICO registration number, IP pseudonymisation mode, retention period, and Critical Risk email alert address.
- **PHP Middleware**: Live preview, copy, or download customized PHP 8.1+ code ready for deployment.

### Production Build
```bash
npm run build
npm run preview
```

---

## How to Use the PHP Library in Your PHP App

You do not need Node.js to use the PHP library in production. Simply copy the `/php` folder to your server:

### 1. Database Setup
Run `/php/schema.sql` against your database (SQLite, MySQL, or PostgreSQL):

```bash
# For SQLite:
sqlite3 aegis_security_audit.sqlite < php/schema.sql
```

### 2. Include in Your PHP Endpoint

```php
<?php
declare(strict_types=1);

require_once __DIR__ . '/php/AegisGuard.php';

use AegisSecurity\AegisGuard;

// 1. Initialise PDO (SQLite or MySQL)
$pdo = new PDO('sqlite:' . __DIR__ . '/aegis_security_audit.sqlite');

// 2. Instantiate AegisGuard
$guard = new AegisGuard(
    pdo: $pdo,
    secretKey: getenv('AEGIS_HMAC_SECRET') ?: 'your-secure-salt-here',
    organizationName: 'Your Company Name Ltd',
    icoRegNumber: 'ZB123456',
    dpoContact: 'dpo@yourcompany.co.uk'
);

// 3. Screen incoming POST input (SMTP form, Direct Message, or Webhook)
$result = $guard->screenRequest($_POST, $_SERVER, 'smtp_mail');

if ($result['verdict'] === 'BLOCK') {
    http_response_code(403);
    echo json_encode(['error' => 'Blocked by security screening', 'audit_id' => $result['audit_id']]);
    exit;
}

if ($result['verdict'] === 'CHALLENGE') {
    http_response_code(429);
    echo json_encode(['error' => 'Verification or banner agreement required']);
    exit;
}

// 4. Safe to execute PHPMailer or deliver Direct Message
// mail($safeRecipient, $safeSubject, $safeBody);
```

### 3. Embed the UK Regulatory Banner & Telemetry Hook
Add this single line inside your HTML layout (before `</body>`):

```php
<?php include_once __DIR__ . '/php/aegis-uk-banner.php'; ?>
```

---

## BuruOps Attribution & Licensing

This project is licensed under the **MIT License with Attribution**.

### Attribution Requirement
You are completely free to use, modify, distribute, and embed this software in private or commercial applications under the condition that you retain visible attribution to **BuruOps**:

- In source code files: Keep the header comment `@author BuruOps (engr.buru@gmail.com)`.
- In public repositories / applications: Include a link or note stating:  
  *Powered by [BuruOps AegisPHP](https://github.com/buruops/aegis-php)*.

For questions, security disclosures, or collaboration:  
**Engr. Buru** &bull; [engr.buru@gmail.com](mailto:engr.buru@gmail.com) &bull; **BuruOps**

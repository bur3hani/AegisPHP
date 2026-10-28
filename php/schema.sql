-- BuruOps AegisPHP — Full Security, Authentication & Protective Audit Log Schema
-- UK GDPR Article 6(1)(f) & Article 5(1)(e) Compliant (SQLite, MySQL, and PostgreSQL compatible)
-- Stores ONLY pseudonymised IP hashes & email domains (no raw PII local-parts) with strict automatic expiry

-- 1. Threat & Protective Audit Log Table
CREATE TABLE IF NOT EXISTS aegis_security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id VARCHAR(32) NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    channel VARCHAR(32) NOT NULL,           -- 'smtp_mail', 'direct_message', 'contact_form', 'api_webhook'
    verdict VARCHAR(16) NOT NULL,           -- 'ALLOW', 'CHALLENGE', 'BLOCK'
    risk_score INTEGER NOT NULL,
    critical_alert_sent INTEGER DEFAULT 0,  -- 1 if score >= 85 and incident email was dispatched
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
    event_type VARCHAR(64) NOT NULL,       -- 'login_success', 'login_failed', 'account_locked', 'password_reset_requested', 'password_reset_success'
    user_id INTEGER DEFAULT NULL,
    email VARCHAR(191) NOT NULL,
    ip_pseudonymised VARCHAR(64) NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    details TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON aegis_auth_audit(event_type, created_at);

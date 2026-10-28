<?php
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

    /**
     * Creates a new user with secure password provisioning.
     * If no password is provided, one is generated via CSPRNG.
     *
     * @return array{id: int, uuid: string, email: string, name: string, role: string, provisioned_password: ?string}
     */
    public function createUser(
        string $email,
        string $name,
        string $role = 'responder',
        ?string $password = null,
        bool $mustChangePassword = false
    ): array {
        $cleanEmail = strtolower(trim($email));
        if (!filter_var($cleanEmail, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('Invalid RFC 5322 email address.');
        }

        $allowedRoles = ['admin', 'responder', 'auditor', 'readonly'];
        if (!in_array($role, $allowedRoles, true)) {
            throw new InvalidArgumentException('Invalid role. Allowed: ' . implode(', ', $allowedRoles));
        }

        // Check for duplicates
        $stmt = $this->pdo->prepare('SELECT id FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        if ($stmt->fetch()) {
            throw new RuntimeException('A user with this email address already exists.');
        }

        $provisionedPassword = null;
        if ($password === null || trim($password) === '') {
            $provisionedPassword = AegisVault::generateSecurePassword(18);
            $hash = AegisVault::hashPassword($provisionedPassword);
            $mustChangePassword = true;
        } else {
            $hash = AegisVault::hashPassword($password);
        }

        $uuid = bin2hex(random_bytes(16));

        $stmt = $this->pdo->prepare(
            'INSERT INTO aegis_users (uuid, email, name, password_hash, role, status, must_change_password, created_at, updated_at)
             VALUES (:uuid, :email, :name, :hash, :role, "active", :must_change, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([
            ':uuid'        => $uuid,
            ':email'       => $cleanEmail,
            ':name'        => trim($name),
            ':hash'        => $hash,
            ':role'        => $role,
            ':must_change' => $mustChangePassword ? 1 : 0,
        ]);

        $userId = (int) $this->pdo->lastInsertId();

        $this->logAuthEvent('user_created', $userId, $cleanEmail, true, "Role: {$role}");

        return [
            'id'                   => $userId,
            'uuid'                 => $uuid,
            'email'                => $cleanEmail,
            'name'                 => trim($name),
            'role'                 => $role,
            'must_change_password' => $mustChangePassword,
            'provisioned_password' => $provisionedPassword,
        ];
    }

    /**
     * Authenticates a user with rate-limiting and brute-force lockout.
     *
     * @return array{authenticated: bool, user: ?array, error: ?string}
     */
    public function authenticate(string $email, string $password, string $clientIp = '0.0.0.0'): array
    {
        $cleanEmail = strtolower(trim($email));

        $stmt = $this->pdo->prepare('SELECT * FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->logAuthEvent('login_failed', null, $cleanEmail, false, 'User not found', $clientIp);
            return ['authenticated' => false, 'user' => null, 'error' => 'Invalid credentials.'];
        }

        if ($user['status'] !== 'active') {
            $this->logAuthEvent('login_blocked', (int) $user['id'], $cleanEmail, false, 'Account inactive/disabled', $clientIp);
            return ['authenticated' => false, 'user' => null, 'error' => 'This account has been disabled.'];
        }

        // Check Lockout
        if ($user['locked_until'] !== null) {
            $lockedUntilTs = strtotime($user['locked_until']);
            if ($lockedUntilTs > time()) {
                $minsLeft = (int) ceil(($lockedUntilTs - time()) / 60);
                $this->logAuthEvent('login_locked', (int) $user['id'], $cleanEmail, false, "Locked for {$minsLeft}m", $clientIp);
                return [
                    'authenticated' => false,
                    'user'          => null,
                    'error'         => "Account locked due to consecutive failed attempts. Try again in {$minsLeft} minutes.",
                ];
            }
        }

        // Verify password in constant time
        if (!AegisVault::verifyPassword($password, $user['password_hash'])) {
            $failedAttempts = (int) $user['failed_attempts'] + 1;
            $lockedUntil = null;

            if ($failedAttempts >= self::MAX_FAILED_ATTEMPTS) {
                $lockedUntil = date('Y-m-d H:i:s', time() + (self::LOCKOUT_MINUTES * 60));
                $this->logAuthEvent('account_locked', (int) $user['id'], $cleanEmail, false, "Locked after {$failedAttempts} attempts", $clientIp);
            } else {
                $this->logAuthEvent('login_failed', (int) $user['id'], $cleanEmail, false, "Attempt {$failedAttempts}", $clientIp);
            }

            $updateStmt = $this->pdo->prepare('UPDATE aegis_users SET failed_attempts = :fa, locked_until = :lu, updated_at = CURRENT_TIMESTAMP WHERE id = :id');
            $updateStmt->execute([
                ':fa' => $failedAttempts,
                ':lu' => $lockedUntil,
                ':id' => $user['id'],
            ]);

            return ['authenticated' => false, 'user' => null, 'error' => 'Invalid credentials.'];
        }

        // Successful Authentication: reset failed attempts
        $updateStmt = $this->pdo->prepare('UPDATE aegis_users SET failed_attempts = 0, locked_until = NULL, last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = :id');
        $updateStmt->execute([':id' => $user['id']]);

        $this->logAuthEvent('login_success', (int) $user['id'], $cleanEmail, true, 'Authenticated', $clientIp);

        // Strip password hash from returned record
        unset($user['password_hash']);

        return [
            'authenticated' => true,
            'user'          => $user,
            'error'         => null,
        ];
    }

    /**
     * Generates a time-limited (15-min) single-use password reset token.
     *
     * @return array{token: string, expires_at: string}|null
     */
    public function createPasswordResetRequest(string $email, string $clientIp = '0.0.0.0'): ?array
    {
        $cleanEmail = strtolower(trim($email));

        $stmt = $this->pdo->prepare('SELECT id, status FROM aegis_users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $cleanEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || $user['status'] !== 'active') {
            // Constant-time dummy delay to mitigate user enumeration
            usleep(random_int(100000, 200000));
            return null;
        }

        $tokenData = AegisVault::generateOnetimeToken();
        $expiresAt = date('Y-m-d H:i:s', time() + (self::RESET_TOKEN_EXPIRY_MINUTES * 60));

        // Invalidate any older pending tokens for this user
        $delStmt = $this->pdo->prepare('UPDATE aegis_password_resets SET used_at = CURRENT_TIMESTAMP WHERE user_id = :uid AND used_at IS NULL');
        $delStmt->execute([':uid' => $user['id']]);

        // Insert new token hash
        $insStmt = $this->pdo->prepare(
            'INSERT INTO aegis_password_resets (user_id, token_hash, expires_at, created_at)
             VALUES (:uid, :th, :exp, CURRENT_TIMESTAMP)'
        );
        $insStmt->execute([
            ':uid' => $user['id'],
            ':th'  => $tokenData['token_hash'],
            ':exp' => $expiresAt,
        ]);

        $this->logAuthEvent('password_reset_requested', (int) $user['id'], $cleanEmail, true, 'Token generated', $clientIp);

        return [
            'token'      => $tokenData['raw_token'],
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Completes password reset using a single-use token.
     */
    public function resetPasswordWithToken(string $rawToken, string $newPassword, string $clientIp = '0.0.0.0'): bool
    {
        if (strlen($newPassword) < 12) {
            throw new InvalidArgumentException('New password must be at least 12 characters.');
        }

        $tokenHash = hash('sha256', trim($rawToken));

        $stmt = $this->pdo->prepare(
            'SELECT pr.id AS reset_id, pr.user_id, pr.expires_at, u.email
             FROM aegis_password_resets pr
             JOIN aegis_users u ON u.id = pr.user_id
             WHERE pr.token_hash = :th AND pr.used_at IS NULL
             LIMIT 1'
        );
        $stmt->execute([':th' => $tokenHash]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$record) {
            $this->logAuthEvent('password_reset_failed', null, 'unknown', false, 'Invalid or consumed token', $clientIp);
            return false;
        }

        if (strtotime($record['expires_at']) < time()) {
            $this->logAuthEvent('password_reset_failed', (int) $record['user_id'], $record['email'], false, 'Expired token', $clientIp);
            return false;
        }

        $newHash = AegisVault::hashPassword($newPassword);

        // Update user password and clear any lockout
        $upUser = $this->pdo->prepare(
            'UPDATE aegis_users
             SET password_hash = :hash, failed_attempts = 0, locked_until = NULL, must_change_password = 0, updated_at = CURRENT_TIMESTAMP
             WHERE id = :id'
        );
        $upUser->execute([
            ':hash' => $newHash,
            ':id'   => $record['user_id'],
        ]);

        // Mark token as used
        $upReset = $this->pdo->prepare('UPDATE aegis_password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = :id');
        $upReset->execute([':id' => $record['reset_id']]);

        $this->logAuthEvent('password_reset_success', (int) $record['user_id'], $record['email'], true, 'Password reset via token', $clientIp);

        return true;
    }

    /**
     * Lists users without exposing password hashes.
     *
     * @return list<array>
     */
    public function listUsers(): array
    {
        $stmt = $this->pdo->query(
            'SELECT id, uuid, email, name, role, status, must_change_password, failed_attempts, last_login_at, created_at
             FROM aegis_users
             ORDER BY id ASC'
        );
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Updates user status (active / disabled).
     */
    public function updateUserStatus(int $userId, string $status): bool
    {
        if (!in_array($status, ['active', 'disabled'], true)) {
            throw new InvalidArgumentException('Status must be active or disabled');
        }

        $stmt = $this->pdo->prepare('UPDATE aegis_users SET status = :st, updated_at = CURRENT_TIMESTAMP WHERE id = :id');
        return $stmt->execute([':st' => $status, ':id' => $userId]);
    }

    /**
     * Deletes a user by ID.
     */
    public function deleteUser(int $userId): bool
    {
        $stmt = $this->pdo->prepare('DELETE FROM aegis_users WHERE id = :id');
        return $stmt->execute([':id' => $userId]);
    }

    private function logAuthEvent(string $type, ?int $userId, string $email, bool $success, string $details = '', string $ip = '0.0.0.0'): void
    {
        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO aegis_auth_audit (event_type, user_id, email, ip_pseudonymised, success, details, created_at)
                 VALUES (:et, :uid, :em, :ip, :sc, :dt, CURRENT_TIMESTAMP)'
            );
            $stmt->execute([
                ':et'  => $type,
                ':uid' => $userId,
                ':em'  => $email,
                ':ip'  => substr(hash('sha256', $ip), 0, 16),
                ':sc'  => $success ? 1 : 0,
                ':dt'  => $details,
            ]);
        } catch (\Throwable) {
            // Ignore audit write failure if table does not yet exist
        }
    }
}

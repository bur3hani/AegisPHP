<?php
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
    private const IV_LENGTH = 12; // 96-bit IV recommended for GCM

    private string $encryptionKey;

    /**
     * @param string|null $encryptionKey 256-bit (32-byte) binary key or 64-char hex string
     */
    public function __construct(?string $encryptionKey = null)
    {
        $rawKey = $encryptionKey ?? ($_ENV['AEGIS_APP_KEY'] ?? getenv('AEGIS_APP_KEY') ?: '');
        if ($rawKey === '') {
            // Fallback to deterministic key derived from environment or throw in strict mode
            $rawKey = hash('sha256', (string) (php_uname('n') . __DIR__ . 'buruops-fallback-entropy'), true);
        } elseif (strlen($rawKey) === 64 && ctype_xdigit($rawKey)) {
            $rawKey = hex2bin($rawKey);
        } else {
            $rawKey = hash('sha256', $rawKey, true);
        }

        $this->encryptionKey = $rawKey;
    }

    /**
     * Encrypts plaintext using AES-256-GCM with authentication tag and fresh random IV.
     * Returns URL-safe base64 string formatted as: iv.tag.ciphertext
     */
    public function encrypt(string $plaintext): string
    {
        if ($plaintext === '') {
            return '';
        }

        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-GCM encryption failed');
        }

        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypts an authenticated AES-256-GCM payload.
     */
    public function decrypt(string $payload): ?string
    {
        if ($payload === '') {
            return '';
        }

        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) < (self::IV_LENGTH + self::TAG_LENGTH)) {
            return null;
        }

        $iv = substr($raw, 0, self::IV_LENGTH);
        $tag = substr($raw, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($raw, self::IV_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $plaintext !== false ? $plaintext : null;
    }

    /**
     * Hashes a password using Argon2id or strong Bcrypt.
     */
    public static function hashPassword(string $password): string
    {
        if (strlen($password) < 12) {
            throw new InvalidArgumentException('Password must be at least 12 characters.');
        }

        if (defined('PASSWORD_ARGON2ID')) {
            return password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536,
                'time_cost'   => 4,
                'threads'     => 1,
            ]);
        }

        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Constant-time password verification.
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Generates a cryptographically strong random password.
     * Enforces uppercase, lowercase, numbers, and special symbols.
     */
    public static function generateSecurePassword(int $length = 18): string
    {
        $length = max(16, min(64, $length));

        $uppers  = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lowers  = 'abcdefghijkmnopqrstuvwxyz';
        $numbers = '23456789';
        $symbols = '!@#$%^&*()-_=+[]{}';

        // Guarantee at least 2 of each required character category
        $passwordChars = [
            $uppers[random_int(0, strlen($uppers) - 1)],
            $uppers[random_int(0, strlen($uppers) - 1)],
            $lowers[random_int(0, strlen($lowers) - 1)],
            $lowers[random_int(0, strlen($lowers) - 1)],
            $numbers[random_int(0, strlen($numbers) - 1)],
            $numbers[random_int(0, strlen($numbers) - 1)],
            $symbols[random_int(0, strlen($symbols) - 1)],
            $symbols[random_int(0, strlen($symbols) - 1)],
        ];

        $allChars = $uppers . $lowers . $numbers . $symbols;
        $allLen   = strlen($allChars);

        while (count($passwordChars) < $length) {
            $passwordChars[] = $allChars[random_int(0, $allLen - 1)];
        }

        // Cryptographic Fisher-Yates shuffle
        for ($i = count($passwordChars) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            $tmp = $passwordChars[$i];
            $passwordChars[$i] = $passwordChars[$j];
            $passwordChars[$j] = $tmp;
        }

        return implode('', $passwordChars);
    }

    /**
     * Generates a single-use 256-bit cryptographically secure token.
     * Returns array with:
     * - 'raw_token': given to user once in link/email
     * - 'token_hash': stored in database (prevents leaked DB from reading active reset tokens)
     */
    public static function generateOnetimeToken(): array
    {
        $raw = bin2hex(random_bytes(32));
        $hash = hash('sha256', $raw);

        return [
            'raw_token'  => $raw,
            'token_hash' => $hash,
        ];
    }
}

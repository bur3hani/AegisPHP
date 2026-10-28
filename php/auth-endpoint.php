<?php
/**
 * auth-endpoint.php — Authentication, User Provisioning & Password Reset REST Endpoint
 * Project: BuruOps AegisPHP (https://github.com/buruops/aegis-php)
 * Author: BuruOps (engr.buru@gmail.com)
 * License: MIT License with Attribution (BuruOps)
 */

declare(strict_types=1);

require_once __DIR__ . '/AegisVault.php';
require_once __DIR__ . '/AegisUserManager.php';

use AegisSecurity\AegisVault;
use AegisSecurity\AegisUserManager;

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

$pdo = new PDO('sqlite:' . __DIR__ . '/aegis_security_audit.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Ensure tables exist
$pdo->exec((string) file_get_contents(__DIR__ . '/schema.sql'));

$vault       = new AegisVault();
$userManager = new AegisUserManager($pdo, $vault);

$action = (string) ($_POST['action'] ?? $_GET['action'] ?? '');
$clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

try {
    switch ($action) {
        // 1. Authenticate / Login
        case 'login':
            $email = (string) ($_POST['email'] ?? '');
            $password = (string) ($_POST['password'] ?? '');

            $result = $userManager->authenticate($email, $password, $clientIp);
            if (!$result['authenticated']) {
                http_response_code(401);
                echo json_encode(['success' => false, 'error' => $result['error']]);
                exit;
            }

            // In production, set secure HttpOnly, SameSite=Strict session cookie here
            echo json_encode([
                'success' => true,
                'user'    => $result['user'],
                'message' => 'Authentication successful.',
            ]);
            break;

        // 2. Request Password Reset Token
        case 'request_reset':
            $email = (string) ($_POST['email'] ?? '');
            $tokenData = $userManager->createPasswordResetRequest($email, $clientIp);

            // Always return identical success message to prevent user enumeration
            echo json_encode([
                'success' => true,
                'message' => 'If this email exists in our system, a secure reset token has been generated.',
                // In production, send via email. For local/development, the token is provided:
                'dev_token' => $tokenData['token'] ?? null,
                'expires_at' => $tokenData['expires_at'] ?? null,
            ]);
            break;

        // 3. Complete Password Reset with Token
        case 'reset_password':
            $token = (string) ($_POST['token'] ?? '');
            $newPassword = (string) ($_POST['new_password'] ?? '');

            $success = $userManager->resetPasswordWithToken($token, $newPassword, $clientIp);
            if (!$success) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Reset token is invalid or has expired.']);
                exit;
            }

            echo json_encode([
                'success' => true,
                'message' => 'Password reset successful. You may now log in with your new credentials.',
            ]);
            break;

        // 4. Create New User (Requires Admin authorization)
        case 'create_user':
            $email = (string) ($_POST['email'] ?? '');
            $name = (string) ($_POST['name'] ?? '');
            $role = (string) ($_POST['role'] ?? 'responder');
            $password = !empty($_POST['password']) ? (string) $_POST['password'] : null;

            $created = $userManager->createUser($email, $name, $role, $password);
            echo json_encode([
                'success' => true,
                'user'    => $created,
                'message' => 'User created and password provisioned successfully.',
            ]);
            break;

        // 5. Generate a Cryptographically Secure Password (Utility for UI)
        case 'generate_password':
            $length = isset($_GET['length']) ? (int) $_GET['length'] : 18;
            $password = AegisVault::generateSecurePassword($length);
            echo json_encode([
                'success'  => true,
                'password' => $password,
                'entropy'  => round($length * log(85, 2), 1) . ' bits',
            ]);
            break;

        // 6. List Users
        case 'list_users':
            $users = $userManager->listUsers();
            echo json_encode(['success' => true, 'users' => $users]);
            break;

        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error'   => 'Unknown action requested.',
                'available_actions' => ['login', 'request_reset', 'reset_password', 'create_user', 'generate_password', 'list_users'],
            ]);
            break;
    }
} catch (\Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error'   => $e->getMessage(),
    ]);
}

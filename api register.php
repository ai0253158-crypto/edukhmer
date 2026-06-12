<?php
/**
 * api_register.php — EduKhmer
 * Receives a user registration from smsnew_author (frontend).
 * 1. Saves the user to the `users` table (hashed password).
 * 2. Logs the plain-text credentials + timestamp to
 *    `user_credentials_log` so the admin can see them in the
 *    admin panel under Users → Credential Log.
 *
 * POST JSON body:
 *   { "first":"", "last":"", "email":"", "phone":"", "pass":"" }
 *
 * Response JSON:
 *   { "ok": true }   or   { "ok": false, "error": "..." }
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { http_response_code(405); echo json_encode(['ok'=>false,'error'=>'Method not allowed']); exit; }

require_once __DIR__ . '/database.php';

/* ── Auto-create credentials log table if not exists ── */
$pdo->exec("CREATE TABLE IF NOT EXISTS user_credentials_log (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT,
    username     VARCHAR(160) NOT NULL,
    plain_pass   VARCHAR(255) NOT NULL,
    full_name    VARCHAR(200),
    phone        VARCHAR(30),
    role         VARCHAR(60) DEFAULT 'teacher',
    registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source       ENUM('self','admin') NOT NULL DEFAULT 'self',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

/* ── Parse input ── */
$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

$first = trim($data['first'] ?? '');
$last  = trim($data['last']  ?? '');
$email = trim($data['email'] ?? '');
$phone = trim($data['phone'] ?? '');
$pass  = $data['pass'] ?? '';

/* ── Validate ── */
if (!$first || !$last || !$email || !$pass) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'ទិន្នន័យមិនគ្រប់គ្រាន់']);
    exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'អ៊ីមែលមិនត្រឹមត្រូវ']);
    exit;
}
if (mb_strlen($pass) < 6) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'ពាក្យសម្ងាត់ខ្លីពេក']);
    exit;
}

/* ── Check duplicate email ── */
$exists = $pdo->prepare("SELECT id FROM users WHERE email = ?");
$exists->execute([$email]);
if ($exists->fetch()) {
    http_response_code(409);
    echo json_encode(['ok'=>false,'error'=>'អ៊ីមែលនេះបានចុះឈ្មោះរួចហើយ']);
    exit;
}

/* ── Insert user ── */
try {
    $hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 12]);
    $pdo->prepare(
        "INSERT INTO users (first_name, last_name, email, phone, password, role, is_active)
         VALUES (?, ?, ?, ?, ?, 'teacher', 1)"
    )->execute([$first, $last, $email, $phone, $hash]);

    $userId = (int) $pdo->lastInsertId();

    /* ── Log plain credentials for admin view ── */
    $pdo->prepare(
        "INSERT INTO user_credentials_log (user_id, username, plain_pass, full_name, phone, role, source)
         VALUES (?, ?, ?, ?, ?, 'teacher', 'self')"
    )->execute([$userId, $email, $pass, trim("$first $last"), $phone]);

    echo json_encode(['ok' => true, 'user_id' => $userId]);

} catch (PDOException $e) {
    error_log('[EduKhmer api_register] ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'Server error — ចុះឈ្មោះមិនបាន']);
}
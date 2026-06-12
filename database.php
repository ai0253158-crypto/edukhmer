<?php
/**
 * database.php — EduKhmer Database Connection
 * Include this file in any PHP page that needs database access.
 *
 * Usage:
 *   require_once 'database.php';
 *   $result = $pdo->query("SELECT * FROM users");
 */

// ── Database credentials ─────────────────────────────────────
define('DB_HOST', 'localhost');
define('DB_PORT', '3306');
define('DB_NAME', 'edukhmer');
define('DB_USER', 'root');          // ← change to your MySQL username
define('DB_PASS', '');              // ← change to your MySQL password
define('DB_CHARSET', 'utf8mb4');

// ── Session & security config ────────────────────────────────
define('ADMIN_SESSION_NAME', 'edukhmer_admin');
define('SESSION_LIFETIME',   3600);   // 1 hour (seconds)
define('BCRYPT_COST',        12);

// ── PDO connection (singleton) ───────────────────────────────
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=%s',
            DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
        );
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Never expose DB details to the browser
            error_log('[EduKhmer DB] Connection failed: ' . $e->getMessage());
            http_response_code(500);
            die(json_encode(['error' => 'Database connection failed. Please contact the administrator.']));
        }
    }
    return $pdo;
}

// ── Convenience alias ────────────────────────────────────────
$pdo = getDB();

// ── Session helpers ──────────────────────────────────────────

/**
 * Start a secure admin session.
 */
function startAdminSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_name(ADMIN_SESSION_NAME);
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

/**
 * Check if an admin is currently logged in.
 * Redirects to admin login page if not.
 */
function requireAdminLogin(string $loginPage = 'admin.php'): void {
    startAdminSession();
    if (empty($_SESSION['admin_id'])) {
        header('Location: ' . $loginPage);
        exit;
    }
    // Session timeout check
    if (!empty($_SESSION['last_activity']) &&
        (time() - $_SESSION['last_activity']) > SESSION_LIFETIME) {
        session_unset();
        session_destroy();
        header('Location: ' . $loginPage . '?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

/**
 * Log an admin in and store session data.
 *
 * @param array $admin  Row from the `admins` table
 */
function loginAdmin(array $admin): void {
    startAdminSession();
    session_regenerate_id(true);
    $_SESSION['admin_id']    = $admin['id'];
    $_SESSION['admin_user']  = $admin['username'];
    $_SESSION['admin_name']  = $admin['full_name'];
    $_SESSION['admin_role']  = $admin['role'];
    $_SESSION['last_activity'] = time();

    // Log the login event
    try {
        $db   = getDB();
        $stmt = $db->prepare(
            "INSERT INTO admin_sessions (admin_id, ip_address, user_agent) VALUES (?,?,?)"
        );
        $stmt->execute([
            $admin['id'],
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);

        $db->prepare("UPDATE admins SET last_login = NOW() WHERE id = ?")
           ->execute([$admin['id']]);
    } catch (PDOException $e) {
        error_log('[EduKhmer] loginAdmin log failed: ' . $e->getMessage());
    }
}

/**
 * Log the current admin out.
 */
function logoutAdmin(): void {
    startAdminSession();
    session_unset();
    session_destroy();
}

// ── Password helpers ─────────────────────────────────────────

function hashPassword(string $plain): string {
    return password_hash($plain, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
}

function verifyPassword(string $plain, string $hash): bool {
    return password_verify($plain, $hash);
}

// ── CSRF helpers ─────────────────────────────────────────────

function csrfToken(): string {
    startAdminSession();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(string $token): bool {
    startAdminSession();
    return isset($_SESSION['csrf_token']) &&
           hash_equals($_SESSION['csrf_token'], $token);
}

// ── Sanitise helpers ─────────────────────────────────────────

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function sanitizeInt($value, int $default = 0): int {
    return filter_var($value, FILTER_VALIDATE_INT) !== false
        ? (int) $value
        : $default;
}
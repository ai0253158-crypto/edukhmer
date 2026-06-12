<?php
/**
 * api_categories.php — EduKhmer
 * Returns active dashboard categories as JSON.
 * Called by smsnew_author.php every time the dashboard is shown,
 * so admin changes (add / edit / delete / hide) appear immediately
 * for all users without a page reload.
 *
 * Usage: GET api_categories.php
 * Response: { "categories": [ { "icon":"👨‍🎓", "label":"...", "color":"mi-blue" }, ... ] }
 */

header('Content-Type: application/json; charset=utf-8');
// Allow same-origin requests only (tighten to your domain in production)
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store, no-cache, must-revalidate');

require_once __DIR__ . '/database.php';

try {
    $rows = $pdo->query(
        "SELECT icon, label, color
         FROM dashboard_categories
         WHERE is_active = 1
         ORDER BY sort_order, id"
    )->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['categories' => $rows], JSON_UNESCAPED_UNICODE);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['categories' => [], 'error' => 'DB error']);
}
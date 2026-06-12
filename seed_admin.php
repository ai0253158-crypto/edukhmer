<?php
require_once __DIR__ . '/database.php';

$hash = password_hash('Admin@1234', PASSWORD_BCRYPT, ['cost' => 12]);

$pdo->prepare("
    UPDATE admins SET password = ? WHERE username = 'admin'
")->execute([$hash]);

echo "✅ Admin password hash updated successfully.\n";
echo "Username: admin\n";
echo "Password: Admin@1234\n";
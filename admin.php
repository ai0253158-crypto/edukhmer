<?php
/**
 * EduKhmer — Admin Panel  (admin.php)
 * ─────────────────────────────────────────────────────────────
 * Place this file next to  database.php  in your project root.
 * Access: http://localhost:8080/edukhmer/admin.php
 *
 * Default login
 *   Username : admin
 *   Password : Admin@1234
 * ─────────────────────────────────────────────────────────────
 */

/* ══ Bootstrap ══════════════════════════════════════════════ */
require_once __DIR__ . '/database.php';   // sets up $pdo, helpers
startAdminSession();

/* ══ Route helpers ══════════════════════════════════════════ */
$action  = $_POST['action'] ?? $_GET['action'] ?? '';
$tab     = $_GET['tab']     ?? 'dashboard';
$flash   = ['msg' => '', 'type' => 'success'];

/* ─────────────────────────────────────────────────────────── */
/* LOGIN                                                        */
/* ─────────────────────────────────────────────────────────── */
if ($action === 'login') {
    $u = trim($_POST['username'] ?? '');
    $p =      $_POST['password'] ?? '';
    if ($u && $p) {
        $st = $pdo->prepare(
            "SELECT * FROM admins WHERE (username=? OR email=?) AND is_active=1 LIMIT 1");
        $st->execute([$u, $u]);
        $row = $st->fetch();
        if ($row && verifyPassword($p, $row['password'])) {
            loginAdmin($row);
            header('Location: admin.php'); exit;
        }
    }
    $flash = ['msg' => 'ឈ្មោះអ្នកប្រើ ឬ ពាក្យសម្ងាត់មិនត្រឹមត្រូវ។', 'type' => 'error'];
}

/* ─────────────────────────────────────────────────────────── */
/* LOGOUT                                                       */
/* ─────────────────────────────────────────────────────────── */
if ($action === 'logout') {
    logoutAdmin();
    header('Location: admin.php'); exit;
}

/* ─────────────────────────────────────────────────────────── */
/* Guard — everything below needs a valid session              */
/* ─────────────────────────────────────────────────────────── */
$loggedIn = !empty($_SESSION['admin_id']);
if ($loggedIn) {
    $csrf = csrfToken();

    /* ─── POST actions ──────────────────────────────────── */
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        // CSRF guard
        if (!verifyCsrf($_POST['csrf'] ?? ''))
            die('<p style="color:red;font-family:sans-serif">CSRF mismatch — please go back and try again.</p>');

        /* ── Site Content ──────────────────────────────── */
        if ($action === 'save_content') {
            $key = trim($_POST['section_key'] ?? '');
            $val = trim($_POST['content']     ?? '');
            if ($key) {
                $pdo->prepare(
                    "INSERT INTO site_content (section_key,content,updated_by)
                     VALUES (?,?,?)
                     ON DUPLICATE KEY UPDATE content=VALUES(content), updated_by=VALUES(updated_by)"
                )->execute([$key, $val, $_SESSION['admin_id']]);
                $flash = ['msg' => '✅ ខ្លឹមសារត្រូវបានរក្សាទុក!', 'type' => 'success'];
            }
        }

        /* ── Bulk content save (whole section at once) ─── */
        if ($action === 'save_content_bulk') {
            $pairs = $_POST['pairs'] ?? [];  // pairs[section_key] = value
            foreach ($pairs as $k => $v) {
                $pdo->prepare(
                    "INSERT INTO site_content (section_key,content,updated_by)
                     VALUES (?,?,?)
                     ON DUPLICATE KEY UPDATE content=VALUES(content), updated_by=VALUES(updated_by)"
                )->execute([trim($k), trim($v), $_SESSION['admin_id']]);
            }
            $flash = ['msg' => '✅ ខ្លឹមសារទាំងអស់ត្រូវបានរក្សាទុក!', 'type' => 'success'];
        }

        /* ── Users ─────────────────────────────────────── */
        if ($action === 'save_user') {
            $id    = sanitizeInt($_POST['user_id'] ?? 0);
            $fn    = trim($_POST['first_name'] ?? '');
            $ln    = trim($_POST['last_name']  ?? '');
            $em    = trim($_POST['email']      ?? '');
            $ph    = trim($_POST['phone']      ?? '');
            $validRoles = $pdo->query("SELECT slug FROM user_roles")->fetchAll(PDO::FETCH_COLUMN);
            $role  = in_array($_POST['role'] ?? '', $validRoles)
                     ? $_POST['role'] : ($validRoles[0] ?? 'teacher');
            $actv  = isset($_POST['is_active']) ? 1 : 0;

            if ($id) {
                $pdo->prepare(
                    "UPDATE users SET first_name=?,last_name=?,email=?,phone=?,role=?,is_active=?,updated_at=NOW() WHERE id=?"
                )->execute([$fn,$ln,$em,$ph,$role,$actv,$id]);
                $flash = ['msg' => '✅ អ្នកប្រើប្រាស់ត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $plainPw = !empty($_POST['password']) ? $_POST['password'] : 'EduKhmer@123';
                $pw = hashPassword($plainPw);
                $pdo->prepare(
                    "INSERT INTO users (first_name,last_name,email,phone,password,role,is_active) VALUES (?,?,?,?,?,?,?)"
                )->execute([$fn,$ln,$em,$ph,$pw,$role,$actv]);
                $newUserId = (int)$pdo->lastInsertId();
                $newUserCreatedAt = date('d/m/Y H:i:s');
                // Log credentials so admin can always find them
                try {
                    $pdo->exec("CREATE TABLE IF NOT EXISTS user_credentials_log (
                        id INT AUTO_INCREMENT PRIMARY KEY, user_id INT,
                        username VARCHAR(160) NOT NULL, plain_pass VARCHAR(255) NOT NULL,
                        full_name VARCHAR(200), phone VARCHAR(30), role VARCHAR(60) DEFAULT 'teacher',
                        registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        source ENUM('self','admin') NOT NULL DEFAULT 'self',
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
                    $pdo->prepare("INSERT INTO user_credentials_log (user_id,username,plain_pass,full_name,phone,role,source) VALUES (?,?,?,?,?,?,?)")
                        ->execute([$newUserId,$em,$plainPw,trim("$fn $ln"),$ph,$role,'admin']);
                } catch(PDOException $e) { error_log('[EduKhmer] cred log: '.$e->getMessage()); }
                $flash = [
                    'msg'  => '✅ អ្នកប្រើប្រាស់ថ្មីត្រូវបានបន្ថែម! &nbsp;|&nbsp; 👤 <strong>Username:</strong> '.htmlspecialchars($em,ENT_QUOTES,'UTF-8').' &nbsp;|&nbsp; 🔑 <strong>Password:</strong> '.htmlspecialchars($plainPw,ENT_QUOTES,'UTF-8').' &nbsp;|&nbsp; 📅 <strong>Date:</strong> '.$newUserCreatedAt,
                    'type' => 'success',
                    'persist' => true,
                ];
            }
        }

        if ($action === 'delete_user') {
            $id = sanitizeInt($_POST['user_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ អ្នកប្រើប្រាស់ត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Change user role (category) ──────────────── */
        if ($action === 'change_user_role') {
            $id   = sanitizeInt($_POST['user_id'] ?? 0);
            $role = trim($_POST['role'] ?? 'teacher');
            if ($id && $role) {
                $pdo->prepare("UPDATE users SET role=?, updated_at=NOW() WHERE id=?")->execute([$role, $id]);
            }
            $flash = ['msg' => '✅ តួនាទីអ្នកប្រើប្រាស់ត្រូវបានប្ដូរ!', 'type' => 'success'];
        }

        /* ── User Role Categories ────────────────────── */
        if ($action === 'save_user_role') {
            $rid   = sanitizeInt($_POST['role_id'] ?? 0);
            $slug  = preg_replace('/[^a-z0-9_]/', '', strtolower(trim($_POST['role_slug'] ?? '')));
            $label = trim($_POST['role_label'] ?? '');
            $icon  = trim($_POST['role_icon']  ?? '👤');
            $color = trim($_POST['role_color'] ?? 'b-blue');
            if ($slug && $label) {
                if ($rid) {
                    $pdo->prepare("UPDATE user_roles SET slug=?,label=?,icon=?,color=? WHERE id=?")
                        ->execute([$slug,$label,$icon,$color,$rid]);
                    $flash = ['msg' => '✅ ប្រភេទអ្នកប្រើត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
                } else {
                    try {
                        $pdo->prepare("INSERT INTO user_roles (slug,label,icon,color) VALUES (?,?,?,?)")
                            ->execute([$slug,$label,$icon,$color]);
                        $flash = ['msg' => '✅ ប្រភេទអ្នកប្រើថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
                    } catch (PDOException $e) {
                        $flash = ['msg' => '❌ Slug "'.$slug.'" មានរួចហើយ!', 'type' => 'error'];
                    }
                }
            } else {
                $flash = ['msg' => '❌ សូមបំពេញ Slug និងឈ្មោះ!', 'type' => 'error'];
            }
        }

        if ($action === 'delete_user_role') {
            $rid  = sanitizeInt($_POST['role_id'] ?? 0);
            $slug = trim($_POST['role_slug'] ?? '');
            if ($rid) {
                $cnt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role=?")->execute([$slug])
                    ? $pdo->query("SELECT COUNT(*) FROM users WHERE role='".addslashes($slug)."'")->fetchColumn()
                    : 0;
                if ($cnt > 0) {
                    $flash = ['msg' => '❌ មិនអាចលុបបាន — មានអ្នកប្រើ '.$cnt.' នាក់ ប្រើប្រភេទនេះ!', 'type' => 'error'];
                } else {
                    $pdo->prepare("DELETE FROM user_roles WHERE id=?")->execute([$rid]);
                    $flash = ['msg' => '🗑️ ប្រភេទអ្នកប្រើត្រូវបានលុប!', 'type' => 'success'];
                }
            }
        }

        if ($action === 'bulk_reassign_role') {
            $from = trim($_POST['from_role'] ?? '');
            $to   = trim($_POST['to_role']   ?? '');
            if ($from && $to && $from !== $to) {
                $cnt = $pdo->query("SELECT COUNT(*) FROM users WHERE role='".addslashes($from)."'")->fetchColumn();
                $pdo->prepare("UPDATE users SET role=?, updated_at=NOW() WHERE role=?")->execute([$to, $from]);
                $flash = ['msg' => '✅ ផ្លាស់ប្ដូរអ្នកប្រើ '.$cnt.' នាក់ ពី "'.$from.'" → "'.$to.'"!', 'type' => 'success'];
            }
        }

        /* ── Dashboard Categories ──────────────────────── */
        if ($action === 'save_dash_cat') {
            $id    = sanitizeInt($_POST['cat_id']    ?? 0);
            $icon  = trim($_POST['cat_icon']  ?? '📌');
            $label = trim($_POST['cat_label'] ?? '');
            $color = trim($_POST['cat_color'] ?? 'mi-blue');
            $sort  = sanitizeInt($_POST['cat_sort']  ?? 0);
            $actv  = isset($_POST['is_active']) ? 1 : 0;
            $validColors = ['mi-blue','mi-purple','mi-orange','mi-pink','mi-green','mi-teal',
                            'mi-red','mi-yellow','mi-indigo','mi-cyan','mi-lime','mi-rose',
                            'mi-sky','mi-violet','mi-amber','mi-slate','mi-emerald','mi-fuchsia'];
            if (!in_array($color, $validColors)) $color = 'mi-blue';
            if ($label) {
                if ($id) {
                    $pdo->prepare("UPDATE dashboard_categories SET icon=?,label=?,color=?,is_active=?,sort_order=? WHERE id=?")
                        ->execute([$icon,$label,$color,$actv,$sort,$id]);
                    $flash = ['msg' => '✅ ប្រភេទត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
                } else {
                    $pdo->prepare("INSERT INTO dashboard_categories (icon,label,color,is_active,sort_order) VALUES (?,?,?,?,?)")
                        ->execute([$icon,$label,$color,$actv,$sort]);
                    $flash = ['msg' => '✅ ប្រភេទថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
                }
            } else {
                $flash = ['msg' => '❌ សូមបំពេញឈ្មោះប្រភេទ!', 'type' => 'error'];
            }
        }
        if ($action === 'delete_dash_cat') {
            $id = sanitizeInt($_POST['cat_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM dashboard_categories WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ ប្រភេទត្រូវបានលុប!', 'type' => 'success'];
        }
        if ($action === 'toggle_dash_cat') {
            $id = sanitizeInt($_POST['cat_id'] ?? 0);
            if ($id) { $pdo->prepare("UPDATE dashboard_categories SET is_active = 1 - is_active WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '✅ ស្ថានភាពត្រូវបានប្ដូរ!', 'type' => 'success'];
        }

        /* ── Schools ───────────────────────────────────── */
        if ($action === 'save_school') {
            $id   = sanitizeInt($_POST['school_id'] ?? 0);
            $nm   = trim($_POST['name']     ?? '');
            $prov = trim($_POST['province'] ?? '');
            $addr = trim($_POST['address']  ?? '');
            $ph   = trim($_POST['phone']    ?? '');
            $em   = trim($_POST['email']    ?? '');
            $ac   = isset($_POST['is_active']) ? 1 : 0;
            if ($id) {
                $pdo->prepare("UPDATE schools SET name=?,province=?,address=?,phone=?,email=?,is_active=? WHERE id=?")
                    ->execute([$nm,$prov,$addr,$ph,$em,$ac,$id]);
                $flash = ['msg' => '✅ សាលារៀនត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO schools (name,province,address,phone,email,is_active) VALUES (?,?,?,?,?,?)")
                    ->execute([$nm,$prov,$addr,$ph,$em,$ac]);
                $flash = ['msg' => '✅ សាលារៀនថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_school') {
            $id = sanitizeInt($_POST['school_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM schools WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ សាលារៀនត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Classes ───────────────────────────────────── */
        if ($action === 'save_class') {
            $id   = sanitizeInt($_POST['class_id']  ?? 0);
            $sid  = sanitizeInt($_POST['school_id'] ?? 0) ?: null;
            $tid  = sanitizeInt($_POST['teacher_id']?? 0) ?: null;
            $nm   = trim($_POST['name']          ?? '');
            $gr   = trim($_POST['grade']         ?? '');
            $yr   = trim($_POST['academic_year'] ?? '');
            $ac   = isset($_POST['is_active']) ? 1 : 0;
            if ($id) {
                $pdo->prepare("UPDATE classes SET school_id=?,teacher_id=?,name=?,grade=?,academic_year=?,is_active=? WHERE id=?")
                    ->execute([$sid,$tid,$nm,$gr,$yr,$ac,$id]);
                $flash = ['msg' => '✅ ថ្នាក់រៀនត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO classes (school_id,teacher_id,name,grade,academic_year,is_active) VALUES (?,?,?,?,?,?)")
                    ->execute([$sid,$tid,$nm,$gr,$yr,$ac]);
                $flash = ['msg' => '✅ ថ្នាក់រៀនថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_class') {
            $id = sanitizeInt($_POST['class_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM classes WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ ថ្នាក់រៀនត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Students ──────────────────────────────────── */
        if ($action === 'save_student') {
            $id   = sanitizeInt($_POST['student_id'] ?? 0);
            $cid  = sanitizeInt($_POST['class_id']   ?? 0) ?: null;
            $code = trim($_POST['student_code'] ?? '');
            $fn   = trim($_POST['first_name']   ?? '');
            $ln   = trim($_POST['last_name']    ?? '');
            $gen  = in_array($_POST['gender']??'', ['male','female','other']) ? $_POST['gender'] : null;
            $dob  = trim($_POST['dob']          ?? '') ?: null;
            $pph  = trim($_POST['parent_phone'] ?? '');
            $addr = trim($_POST['address']      ?? '');
            $ac   = isset($_POST['is_active']) ? 1 : 0;
            if ($id) {
                $pdo->prepare("UPDATE students SET class_id=?,student_code=?,first_name=?,last_name=?,gender=?,dob=?,parent_phone=?,address=?,is_active=?,updated_at=NOW() WHERE id=?")
                    ->execute([$cid,$code,$fn,$ln,$gen,$dob,$pph,$addr,$ac,$id]);
                $flash = ['msg' => '✅ ព័ត៌មានសិស្សត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO students (class_id,student_code,first_name,last_name,gender,dob,parent_phone,address,is_active) VALUES (?,?,?,?,?,?,?,?,?)")
                    ->execute([$cid,$code,$fn,$ln,$gen,$dob,$pph,$addr,$ac]);
                $flash = ['msg' => '✅ សិស្សថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_student') {
            $id = sanitizeInt($_POST['student_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM students WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ សិស្សត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Subjects ──────────────────────────────────── */
        if ($action === 'save_subject') {
            $id   = sanitizeInt($_POST['subject_id'] ?? 0);
            $nm   = trim($_POST['name'] ?? '');
            $code = trim($_POST['code'] ?? '');
            $desc = trim($_POST['description'] ?? '');
            $ac   = isset($_POST['is_active']) ? 1 : 0;
            if ($id) {
                $pdo->prepare("UPDATE subjects SET name=?,code=?,description=?,is_active=? WHERE id=?")
                    ->execute([$nm,$code,$desc,$ac,$id]);
                $flash = ['msg' => '✅ មុខវិជ្ជាត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO subjects (name,code,description,is_active) VALUES (?,?,?,?)")
                    ->execute([$nm,$code,$desc,$ac]);
                $flash = ['msg' => '✅ មុខវិជ្ជាថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_subject') {
            $id = sanitizeInt($_POST['subject_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM subjects WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ មុខវិជ្ជាត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Scores ────────────────────────────────────── */
        if ($action === 'save_score') {
            $id   = sanitizeInt($_POST['score_id']   ?? 0);
            $stid = sanitizeInt($_POST['student_id'] ?? 0);
            $suid = sanitizeInt($_POST['subject_id'] ?? 0);
            $cid  = sanitizeInt($_POST['class_id']   ?? 0) ?: null;
            $type = in_array($_POST['score_type']??'', ['midterm','final','assignment','quiz','attendance']) ? $_POST['score_type'] : 'final';
            $sc   = $_POST['score']     !== '' ? (float)$_POST['score']     : null;
            $mx   = $_POST['max_score'] !== '' ? (float)$_POST['max_score'] : 100;
            $note = trim($_POST['note']       ?? '');
            $dat  = trim($_POST['scored_at']  ?? '') ?: null;
            if ($id) {
                $pdo->prepare("UPDATE scores SET student_id=?,subject_id=?,class_id=?,score_type=?,score=?,max_score=?,note=?,scored_at=? WHERE id=?")
                    ->execute([$stid,$suid,$cid,$type,$sc,$mx,$note,$dat,$id]);
                $flash = ['msg' => '✅ ពិន្ទុត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO scores (student_id,subject_id,class_id,score_type,score,max_score,note,scored_at) VALUES (?,?,?,?,?,?,?,?)")
                    ->execute([$stid,$suid,$cid,$type,$sc,$mx,$note,$dat]);
                $flash = ['msg' => '✅ ពិន្ទុថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_score') {
            $id = sanitizeInt($_POST['score_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM scores WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ ពិន្ទុត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Attendance ────────────────────────────────── */
        if ($action === 'save_attendance') {
            $id   = sanitizeInt($_POST['att_id']    ?? 0);
            $stid = sanitizeInt($_POST['student_id']?? 0);
            $cid  = sanitizeInt($_POST['class_id']  ?? 0) ?: null;
            $date = trim($_POST['attend_date'] ?? '') ?: date('Y-m-d');
            $stat = in_array($_POST['status']??'', ['present','absent','late','excused']) ? $_POST['status'] : 'present';
            $note = trim($_POST['note'] ?? '');
            if ($id) {
                $pdo->prepare("UPDATE attendance SET student_id=?,class_id=?,attend_date=?,status=?,note=? WHERE id=?")
                    ->execute([$stid,$cid,$date,$stat,$note,$id]);
                $flash = ['msg' => '✅ វត្តមានត្រូវបានធ្វើបច្ចុប្បន្នភាព!', 'type' => 'success'];
            } else {
                $pdo->prepare("INSERT INTO attendance (student_id,class_id,attend_date,status,note) VALUES (?,?,?,?,?)")
                    ->execute([$stid,$cid,$date,$stat,$note]);
                $flash = ['msg' => '✅ វត្តមានថ្មីត្រូវបានបន្ថែម!', 'type' => 'success'];
            }
        }
        if ($action === 'delete_attendance') {
            $id = sanitizeInt($_POST['att_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM attendance WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ វត្តមានត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Testimonials ──────────────────────────────── */
        if ($action === 'save_testimonial') {
            $id   = sanitizeInt($_POST['t_id'] ?? 0);
            $nm   = trim($_POST['author_name']  ?? '');
            $rl   = trim($_POST['author_role']  ?? '');
            $col  = trim($_POST['avatar_color'] ?? '#0054a6');
            $st   = min(5, max(1, (int)($_POST['stars']    ?? 5)));
            $ct   = trim($_POST['content']      ?? '');
            $ac   = isset($_POST['is_active'])  ? 1 : 0;
            $so   = sanitizeInt($_POST['sort_order'] ?? 0);
            if ($id) {
                $pdo->prepare("UPDATE testimonials SET author_name=?,author_role=?,avatar_color=?,stars=?,content=?,is_active=?,sort_order=? WHERE id=?")
                    ->execute([$nm,$rl,$col,$st,$ct,$ac,$so,$id]);
            } else {
                $pdo->prepare("INSERT INTO testimonials (author_name,author_role,avatar_color,stars,content,is_active,sort_order) VALUES (?,?,?,?,?,?,?)")
                    ->execute([$nm,$rl,$col,$st,$ct,$ac,$so]);
            }
            $flash = ['msg' => '✅ មតិយោបល់ត្រូវបានរក្សាទុក!', 'type' => 'success'];
        }

        if ($action === 'delete_testimonial') {
            $id = sanitizeInt($_POST['t_id'] ?? 0);
            if ($id) { $pdo->prepare("DELETE FROM testimonials WHERE id=?")->execute([$id]); }
            $flash = ['msg' => '🗑️ មតិយោបល់ត្រូវបានលុប!', 'type' => 'success'];
        }

        /* ── Plans ─────────────────────────────────────── */
        if ($action === 'save_plan') {
            $id   = sanitizeInt($_POST['plan_id'] ?? 0);
            $nm   = trim($_POST['name']     ?? '');
            $desc = trim($_POST['subtitle'] ?? '');
            $pr   = trim($_POST['price']    ?? '');
            $pe   = trim($_POST['period']   ?? '');
            $ft   = isset($_POST['is_featured']) ? 1 : 0;
            $ctaL = trim($_POST['cta_label'] ?? '');
            $raw  = trim($_POST['features'] ?? '');
            $arr  = array_values(array_filter(array_map('trim', explode("\n", $raw))));
            $jf   = json_encode($arr, JSON_UNESCAPED_UNICODE);
            if ($id) {
                $pdo->prepare("UPDATE plans SET name=?,subtitle=?,price=?,period=?,is_featured=?,cta_label=?,features=? WHERE id=?")
                    ->execute([$nm,$desc,$pr,$pe,$ft,$ctaL,$jf,$id]);
            }
            $flash = ['msg' => '✅ ផែនការតម្លៃត្រូវបានរក្សាទុក!', 'type' => 'success'];
        }

        /* ── Features section cards ────────────────────── */
        if ($action === 'save_feature') {
            $id    = sanitizeInt($_POST['feat_id'] ?? 0);
            $title = trim($_POST['title']   ?? '');
            $desc  = trim($_POST['desc']    ?? '');
            $ac    = isset($_POST['is_active']) ? 1 : 0;
            if ($id) {
                $pdo->prepare("UPDATE site_features SET title=?,description=?,is_active=? WHERE id=?")
                    ->execute([$title,$desc,$ac,$id]);
            }
            $flash = ['msg' => '✅ Feature card ត្រូវបានរក្សាទុក!', 'type' => 'success'];
        }

        /* ── Admin password ────────────────────────────── */
        if ($action === 'change_password') {
            $cur = $_POST['current_pass'] ?? '';
            $n1  = $_POST['new_pass']     ?? '';
            $n2  = $_POST['confirm_pass'] ?? '';
            $row = $pdo->prepare("SELECT password FROM admins WHERE id=?")->execute([$_SESSION['admin_id']]);
            $row = $pdo->query("SELECT password FROM admins WHERE id=".(int)$_SESSION['admin_id'])->fetch();
            if (!verifyPassword($cur, $row['password'])) {
                $flash = ['msg' => '❌ ពាក្យសម្ងាត់បច្ចុប្បន្នខុស!', 'type' => 'error'];
            } elseif (strlen($n1) < 8) {
                $flash = ['msg' => '❌ ពាក្យសម្ងាត់ថ្មីត្រូវការ ≥ 8 តួ!', 'type' => 'error'];
            } elseif ($n1 !== $n2) {
                $flash = ['msg' => '❌ ពាក្យសម្ងាត់ថ្មីមិនដូចគ្នា!', 'type' => 'error'];
            } else {
                $pdo->prepare("UPDATE admins SET password=? WHERE id=?")
                    ->execute([hashPassword($n1), $_SESSION['admin_id']]);
                $flash = ['msg' => '✅ ពាក្យសម្ងាត់ត្រូវបានប្ដូររួច!', 'type' => 'success'];
            }
        }
    }

    /* ─── Ensure plans table has subtitle + cta_label columns ─ */
    try {
        $pdo->exec("ALTER TABLE plans ADD COLUMN subtitle VARCHAR(200) DEFAULT '' AFTER name");
    } catch(PDOException $e) { /* column already exists */ }
    try {
        $pdo->exec("ALTER TABLE plans ADD COLUMN cta_label VARCHAR(100) DEFAULT '' AFTER period");
    } catch(PDOException $e) { /* column already exists */ }

    /* Ensure site_features table exists */
    $pdo->exec("CREATE TABLE IF NOT EXISTS site_features (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        feat_key    VARCHAR(40) NOT NULL UNIQUE,
        title       VARCHAR(200) NOT NULL,
        description TEXT,
        icon_color  VARCHAR(20) DEFAULT 'fi-blue',
        is_active   TINYINT(1) DEFAULT 1,
        sort_order  INT DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    /* Seed default features if empty */
    $fc = $pdo->query("SELECT COUNT(*) FROM site_features")->fetchColumn();
    if ($fc == 0) {
        $features_seed = [
            ['feat1','ចុះវត្តមានតាម QR Code','ស្កែ QR ដើម្បីចុះវត្តមានដោយស្វ័យប្រវត្តិ។ ទំនាក់ទំនងជាមួយអ្នកដឹកនាំ និងមាតាបិតាភ្លាមៗ ប្រសិនបើសិស្សខ្វះ។','fi-blue',1,1],
            ['feat2','បញ្ចូលពិន្ទុបានលឿន','វាយបញ្ចូលពិន្ទុជាក្រុម ឬម្នាក់ម្នាក់ ហើយប្រព័ន្ធគណនា GPA ដោយស្វ័យប្រវត្តិ ភ្ជាប់ជាមួយ Excel។','fi-orange',1,2],
            ['feat3','ចែករំលែកមុខវិជ្ជាតាមអ៊ីនធឺណិត','ផ្ទុកឯកសារ PDF ឬ PowerPoint ដើម្បីឱ្យសិស្សសិក្សាពីផ្ទះ ជាមួយប្រព័ន្ធតាមដានការអានរបស់ពួកគេ។','fi-green',1,3],
            ['feat4','របាយការណ៍ & ស្ថិតិ','ភ្ជាប់ Chart ស្ទើរតែគ្រប់ប្រភេទ ដើម្បីជួយអ្នកយល់ដឹងពីវឌ្ឍនភាពសិស្ស និងចំណុចដែលត្រូវកែលម្អ។','fi-purple',1,4],
            ['feat5','ជូនដំណឹងដោយស្វ័យប្រវត្តិ','ផ្ញើ SMS ឬ Telegram ដល់ មាតាបិតា ពេលសិស្សខ្វះ ឬពិន្ទុប្រឡងចេញ ដោយគ្មានការស្ម័គ្រចិត្ត។','fi-teal',1,5],
            ['feat6','ទិន្នន័យសុវត្ថិភាព ១០០%','ប្រព័ន្ធការពារ SSL ការ Backup ប្រចាំថ្ងៃ និងការ Login ពីរជំហាន ដើម្បីការពារព័ត៌មានរបស់អ្នក។','fi-red',1,6],
        ];
        $ins = $pdo->prepare("INSERT INTO site_features (feat_key,title,description,icon_color,is_active,sort_order) VALUES (?,?,?,?,?,?)");
        foreach ($features_seed as $f) $ins->execute($f);
    }

    /* Ensure user_roles table exists and has defaults */
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_roles (
        id        INT AUTO_INCREMENT PRIMARY KEY,
        slug      VARCHAR(60) NOT NULL UNIQUE,
        label     VARCHAR(100) NOT NULL,
        icon      VARCHAR(20)  DEFAULT '👤',
        color     VARCHAR(20)  DEFAULT 'b-blue',
        sort_order INT DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    /* Seed defaults if empty */
    if ($pdo->query("SELECT COUNT(*) FROM user_roles")->fetchColumn() == 0) {
        $pdo->exec("INSERT INTO user_roles (slug,label,icon,color,sort_order) VALUES
            ('teacher','Teacher','👨‍🏫','b-blue',1),
            ('student','Student','👨‍🎓','b-green',2),
            ('parent','Parent','👨‍👩‍👧','b-orange',3)");
    }
    $userRoles    = $pdo->query("SELECT * FROM user_roles ORDER BY sort_order, id")->fetchAll();
    $roleMap      = array_column($userRoles, 'label', 'slug');
    $roleIconMap  = array_column($userRoles, 'icon',  'slug');
    $roleColorMap = array_column($userRoles, 'color', 'slug');
    $roleSlugs    = array_column($userRoles, 'slug');

    /* ─── Dashboard Categories table ─────────────────── */
    $pdo->exec("CREATE TABLE IF NOT EXISTS dashboard_categories (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        icon       VARCHAR(20)  NOT NULL DEFAULT '📌',
        label      VARCHAR(200) NOT NULL,
        color      VARCHAR(20)  NOT NULL DEFAULT 'mi-blue',
        is_active  TINYINT(1)   NOT NULL DEFAULT 1,
        sort_order INT          NOT NULL DEFAULT 0,
        created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    if ($pdo->query("SELECT COUNT(*) FROM dashboard_categories")->fetchColumn() == 0) {
        $seed_cats = [
            ['icon'=>'👨‍🎓','label'=>'បញ្ចូលព័ត៌មានសិស្ស','color'=>'mi-blue','sort'=>1],
            ['icon'=>'👥','label'=>'បញ្ជីសិស្ស','color'=>'mi-purple','sort'=>2],
            ['icon'=>'⊞','label'=>'ចុះឈ្មោះ​ចូលថ្នាក់','color'=>'mi-orange','sort'=>3],
            ['icon'=>'📅','label'=>'បញ្ជីក្រុមប្រឡងពិន្ទុ','color'=>'mi-pink','sort'=>4],
            ['icon'=>'📒','label'=>'បណ្ណាល័យ​ភារកិច្ចអប់រំ','color'=>'mi-indigo','sort'=>5],
            ['icon'=>'📤','label'=>'បញ្ជូនការងារ – ទៅអ្នកណា','color'=>'mi-teal','sort'=>6],
            ['icon'=>'✏️','label'=>'បញ្ចូលពិន្ទុ','color'=>'mi-green','sort'=>7],
            ['icon'=>'⊞','label'=>'តារាងពិន្ទុសរុប','color'=>'mi-cyan','sort'=>8],
            ['icon'=>'📊','label'=>'តារាងចំណាត់ថ្នាក់','color'=>'mi-red','sort'=>9],
            ['icon'=>'📉','label'=>'វិភាគទិន្នន័យសរុប','color'=>'mi-rose','sort'=>10],
            ['icon'=>'🎯','label'=>'វិភាគការសិក្សា','color'=>'mi-amber','sort'=>11],
            ['icon'=>'📆','label'=>'វិភាគតារាងមុខវិជ្ជា','color'=>'mi-yellow','sort'=>12],
            ['icon'=>'📁','label'=>'ឯកសារក្នុងទូឯកសារ','color'=>'mi-violet','sort'=>13],
            ['icon'=>'🏅','label'=>'តារាងកិច្ចការ','color'=>'mi-lime','sort'=>14],
            ['icon'=>'⏱️','label'=>'បញ្ជូនកម្មវិធីបណ្ណប័ត្រ','color'=>'mi-sky','sort'=>15],
            ['icon'=>'📖','label'=>'ស្វែងរកព័ត៌មាន','color'=>'mi-emerald','sort'=>16],
        ];
        $ins_cat = $pdo->prepare("INSERT INTO dashboard_categories (icon,label,color,is_active,sort_order) VALUES (?,?,?,1,?)");
        foreach ($seed_cats as $r) $ins_cat->execute([$r['icon'],$r['label'],$r['color'],$r['sort']]);
    }
    $dashCategories = $pdo->query("SELECT * FROM dashboard_categories ORDER BY sort_order, id")->fetchAll();

    /* ─── User Credentials Log table ─────────────────── */
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_credentials_log (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        user_id       INT,
        username      VARCHAR(160) NOT NULL,
        plain_pass    VARCHAR(255) NOT NULL,
        full_name     VARCHAR(200),
        phone         VARCHAR(30),
        role          VARCHAR(60) DEFAULT 'teacher',
        registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source        ENUM('self','admin') NOT NULL DEFAULT 'self',
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $credLogs = $pdo->query(
        "SELECT cl.*, u.is_active, u.first_name, u.last_name
         FROM user_credentials_log cl
         LEFT JOIN users u ON u.id = cl.user_id
         ORDER BY cl.registered_at DESC"
    )->fetchAll();

    $stats = [
        'users'    => $pdo->query("SELECT COUNT(*) FROM users WHERE is_active=1")->fetchColumn(),
        'students' => $pdo->query("SELECT COUNT(*) FROM students WHERE is_active=1")->fetchColumn(),
        'classes'  => $pdo->query("SELECT COUNT(*) FROM classes  WHERE is_active=1")->fetchColumn(),
        'schools'  => $pdo->query("SELECT COUNT(*) FROM schools  WHERE is_active=1")->fetchColumn(),
    ];

    $cRows   = $pdo->query("SELECT * FROM site_content ORDER BY section_key")->fetchAll();
    $cMap    = array_column($cRows, 'content', 'section_key');
    $cv      = fn(string $k, string $d='') => $cMap[$k] ?? $d;

    $users        = $pdo->query("SELECT * FROM users ORDER BY created_at DESC LIMIT 200")->fetchAll();
    $testimonials = $pdo->query("SELECT * FROM testimonials ORDER BY sort_order, id")->fetchAll();
    $plans        = $pdo->query("SELECT * FROM plans ORDER BY id")->fetchAll();
    $siteFeatures = $pdo->query("SELECT * FROM site_features ORDER BY sort_order")->fetchAll();
    $recentUsers  = $pdo->query("SELECT * FROM users ORDER BY created_at DESC LIMIT 6")->fetchAll();
    $me           = $pdo->query("SELECT * FROM admins WHERE id=".(int)$_SESSION['admin_id'])->fetch();

    /* ─── Extended data for new tabs ─────────────────── */
    $schools  = $pdo->query("SELECT * FROM schools ORDER BY name")->fetchAll();
    $classes  = $pdo->query(
        "SELECT c.*, s.name AS school_name,
                CONCAT(u.first_name,' ',u.last_name) AS teacher_name
         FROM classes c
         LEFT JOIN schools s ON s.id=c.school_id
         LEFT JOIN users   u ON u.id=c.teacher_id
         ORDER BY c.name"
    )->fetchAll();
    $students = $pdo->query(
        "SELECT st.*, cl.name AS class_name
         FROM students st
         LEFT JOIN classes cl ON cl.id=st.class_id
         ORDER BY st.last_name, st.first_name LIMIT 500"
    )->fetchAll();
    $subjects = $pdo->query("SELECT * FROM subjects ORDER BY name")->fetchAll();
    $scores   = $pdo->query(
        "SELECT sc.*,
                CONCAT(st.first_name,' ',st.last_name) AS student_name,
                su.name AS subject_name
         FROM scores sc
         LEFT JOIN students st ON st.id=sc.student_id
         LEFT JOIN subjects su ON su.id=sc.subject_id
         ORDER BY sc.scored_at DESC, sc.id DESC LIMIT 300"
    )->fetchAll();
    $attendance = $pdo->query(
        "SELECT a.*,
                CONCAT(st.first_name,' ',st.last_name) AS student_name,
                cl.name AS class_name
         FROM attendance a
         LEFT JOIN students st ON st.id=a.student_id
         LEFT JOIN classes  cl ON cl.id=a.class_id
         ORDER BY a.attend_date DESC, a.id DESC LIMIT 300"
    )->fetchAll();
    $teachers = $pdo->query("SELECT id, CONCAT(first_name,' ',last_name) AS full_name FROM users WHERE role='teacher' AND is_active=1 ORDER BY first_name")->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="km">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EduKhmer — Admin Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ═══ Reset & Variables ══════════════════════════════════════ */
:root{
  --blue:#0054a6;--blue-d:#003d7a;--blue-l:#e8f0fb;--blue-m:#1a73e8;
  --accent:#ff6b00;--acc-l:#fff3e8;
  --green:#1b8a4c;--green-l:#e8f5ee;
  --red:#e53935;--red-l:#fdecea;
  --orange:#c2410c;--orange-l:#fff3e8;
  --text:#1a1a2e;--muted:#5a6475;--light:#8a93a2;
  --surface:#f4f6fb;--white:#fff;--border:#e0e7ef;
  --sidebar:230px;--topbar:56px;
  --r:10px;--r-lg:16px;
  --sh:0 2px 12px rgba(0,84,166,.08);--sh-lg:0 8px 28px rgba(0,84,166,.14);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:'Kantumruy Pro',sans-serif;background:var(--surface);color:var(--text);font-size:14px;line-height:1.6}
a{text-decoration:none;color:inherit}
input,select,textarea,button{font-family:inherit;font-size:inherit}

/* ═══ Utility ════════════════════════════════════════════════ */
.hidden{display:none!important}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.72rem;font-weight:600}
.b-blue  {background:var(--blue-l); color:var(--blue)}
.b-green {background:var(--green-l);color:var(--green)}
.b-red   {background:var(--red-l);  color:var(--red)}
.b-orange{background:var(--orange-l);color:var(--orange)}
.b-muted {background:#f1f5f9;       color:var(--muted)}

/* ═══ Login Page ═════════════════════════════════════════════ */
.login-bg{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#0054a6 0%,#001f4d 100%);
  position:relative;overflow:hidden;
}
.login-bg::before{
  content:'';position:absolute;inset:0;
  background-image:linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px);
  background-size:44px 44px;
}
.login-card{
  position:relative;background:white;border-radius:20px;
  width:100%;max-width:420px;padding:44px 40px;
  box-shadow:0 24px 64px rgba(0,0,0,.28);
}
.login-logo{text-align:center;margin-bottom:32px}
.login-icon{
  width:64px;height:64px;background:var(--blue);border-radius:18px;
  display:flex;align-items:center;justify-content:center;
  margin:0 auto 14px;font-size:1.8rem;
  box-shadow:0 8px 24px rgba(0,84,166,.35);
}
.login-logo h1{font-size:1.5rem;font-weight:700;color:var(--blue)}
.login-logo p{font-size:.83rem;color:var(--muted);margin-top:3px}
.login-hint{
  background:var(--blue-l);border-radius:var(--r);
  padding:10px 14px;font-size:.78rem;color:var(--muted);
  margin-bottom:20px;text-align:center;border:1px dashed #bed2f0;
}
.login-hint strong{color:var(--blue)}

/* ═══ Form Elements ══════════════════════════════════════════ */
.fg{margin-bottom:16px}
.fg label{display:block;font-size:.8rem;font-weight:700;color:var(--text);margin-bottom:5px;letter-spacing:.01em}
.fg input,.fg select,.fg textarea{
  width:100%;border:1.5px solid var(--border);border-radius:9px;
  padding:10px 13px;font-size:.9rem;color:var(--text);outline:none;
  transition:border-color .2s,box-shadow .2s;background:white;
}
.fg input:focus,.fg select:focus,.fg textarea:focus{
  border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,84,166,.1);
}
.fg textarea{resize:vertical;min-height:80px}
.fg.half{display:inline-block;width:calc(50% - 6px)}
.fg.half+.fg.half{margin-left:12px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-row.c3{grid-template-columns:1fr 1fr 1fr}
.chk{display:flex;align-items:center;gap:8px;cursor:pointer;font-size:.85rem;margin-top:4px}
.chk input[type=checkbox]{width:16px;height:16px;accent-color:var(--blue)}

/* Buttons */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:7px;
  padding:10px 22px;border:none;border-radius:9px;
  font-size:.88rem;font-weight:600;cursor:pointer;transition:all .18s;
}
.btn svg{flex-shrink:0}
.btn-blue{background:var(--blue);color:white}.btn-blue:hover{background:var(--blue-d);transform:translateY(-1px)}
.btn-green{background:var(--green);color:white}.btn-green:hover{background:#145c35}
.btn-outline{background:transparent;border:1.5px solid var(--border);color:var(--muted)}.btn-outline:hover{border-color:var(--blue);color:var(--blue)}
.btn-ghost{background:var(--blue-l);color:var(--blue);border:none}.btn-ghost:hover{background:#d0e3f8}
.btn-red{background:var(--red-l);color:var(--red);border:none}.btn-red:hover{background:#fca5a5;color:#7f1d1d}
.btn-sm{padding:6px 14px;font-size:.78rem}
.btn-full{width:100%;padding:13px}
.btn-save{background:var(--blue);color:white;border:none;border-radius:8px;padding:8px 18px;font-size:.82rem;font-weight:600;cursor:pointer}
.btn-save:hover{background:var(--blue-d)}

/* Alert flash */
.alert{
  padding:11px 16px;border-radius:var(--r);font-size:.85rem;
  margin-bottom:18px;display:flex;align-items:center;gap:8px;
}
.alert-success{background:var(--green-l);color:var(--green);border:1px solid #86efac}
.alert-error  {background:var(--red-l);  color:var(--red);  border:1px solid #fca5a5}

/* ═══ Admin Layout ═══════════════════════════════════════════ */
.layout{display:flex;min-height:100vh}

/* Sidebar */
.sidebar{
  width:var(--sidebar);min-height:100vh;
  background:linear-gradient(180deg,#0a2f6b 0%,#001540 100%);
  position:fixed;top:0;left:0;bottom:0;
  display:flex;flex-direction:column;overflow-y:auto;z-index:60;
}
.sb-logo{
  padding:20px 16px 18px;border-bottom:1px solid rgba(255,255,255,.08);
  display:flex;align-items:center;gap:11px;
}
.sb-logo-icon{
  width:40px;height:40px;background:var(--blue-m);border-radius:11px;
  display:flex;align-items:center;justify-content:center;font-size:1.2rem;flex-shrink:0;
}
.sb-logo-text{color:white;font-size:1rem;font-weight:700;line-height:1.2}
.sb-logo-sub{color:rgba(255,255,255,.45);font-size:.67rem}
.sb-nav{padding:12px 10px;flex:1}
.sb-sec{
  font-size:.63rem;text-transform:uppercase;letter-spacing:.09em;
  color:rgba(255,255,255,.35);padding:10px 8px 4px;
}
.sb-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 11px;border-radius:9px;
  color:rgba(255,255,255,.65);font-size:.83rem;font-weight:500;
  margin-bottom:1px;cursor:pointer;transition:all .17s;
  text-decoration:none;
}
.sb-item:hover{background:rgba(255,255,255,.1);color:white}
.sb-item.active{background:rgba(255,255,255,.16);color:white;font-weight:700}
.sb-item .ico{font-size:.95rem;width:20px;text-align:center;flex-shrink:0}
.sb-foot{padding:12px 10px;border-top:1px solid rgba(255,255,255,.08)}

/* Topbar */
.topbar{
  position:fixed;top:0;left:var(--sidebar);right:0;height:var(--topbar);z-index:50;
  background:white;border-bottom:1px solid var(--border);
  display:flex;align-items:center;padding:0 24px;gap:16px;
  box-shadow:0 1px 4px rgba(0,0,0,.04);
}
.topbar-title{font-size:1rem;font-weight:700;flex:1}
.admin-pill{
  display:flex;align-items:center;gap:9px;
  background:var(--blue-l);border-radius:24px;padding:5px 14px 5px 6px;
}
.admin-av{
  width:28px;height:28px;border-radius:50%;background:var(--blue);
  color:white;display:flex;align-items:center;justify-content:center;
  font-size:.75rem;font-weight:700;
}
.admin-name{font-size:.8rem;font-weight:600;color:var(--blue)}
.admin-role{font-size:.68rem;color:var(--muted)}

/* Main content */
.main{margin-left:var(--sidebar);margin-top:var(--topbar);flex:1;padding:24px}

/* ═══ Cards & Tables ═════════════════════════════════════════ */
.card{background:white;border-radius:var(--r-lg);box-shadow:var(--sh);margin-bottom:22px;overflow:hidden}
.card-head{
  padding:14px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.card-head h3{font-size:.93rem;font-weight:700;display:flex;align-items:center;gap:7px}
.card-body{padding:20px}
.card-body.np{padding:0}

.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{
  background:white;border-radius:var(--r-lg);padding:18px 20px;
  box-shadow:var(--sh);display:flex;align-items:center;gap:14px;
}
.stat-icon{width:50px;height:50px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0}
.stat-val{font-size:1.65rem;font-weight:700;color:var(--blue);line-height:1}
.stat-lbl{font-size:.74rem;color:var(--muted);margin-top:2px}

table{width:100%;border-collapse:collapse}
th{
  font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
  padding:9px 14px;text-align:left;background:var(--surface);
  border-bottom:1px solid var(--border);white-space:nowrap;
}
td{padding:10px 14px;border-bottom:1px solid var(--border);font-size:.84rem;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#fafbff}
.td-actions{display:flex;gap:6px;align-items:center}

/* ═══ Section Heading ════════════════════════════════════════ */
.sec-head{margin-bottom:20px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.sec-head-left h2{font-size:1.05rem;font-weight:700}
.sec-head-left p{font-size:.81rem;color:var(--muted);margin-top:2px}

/* ═══ Inline Edit ════════════════════════════════════════════ */
.field-row{
  display:flex;align-items:flex-end;gap:10px;
  padding:12px 0;border-bottom:1px solid var(--border);
}
.field-row:last-child{border-bottom:none}
.field-row-inner{flex:1}
.field-row-inner label{font-size:.75rem;font-weight:700;color:var(--muted);display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.field-row-inner input,.field-row-inner textarea{
  width:100%;border:1.5px solid var(--border);border-radius:8px;
  padding:9px 12px;font-size:.88rem;outline:none;
  transition:border-color .2s;background:white;
}
.field-row-inner input:focus,.field-row-inner textarea:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,84,166,.08)}

/* ═══ Modal ══════════════════════════════════════════════════ */
.modal-bg{
  display:none;position:fixed;inset:0;z-index:200;
  background:rgba(0,0,0,.5);backdrop-filter:blur(3px);
  align-items:center;justify-content:center;padding:1rem;
}
.modal-bg.open{display:flex;animation:fadeIn .18s ease}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.modal{
  background:white;border-radius:18px;width:100%;max-width:540px;
  max-height:90vh;overflow-y:auto;
  animation:slideUp .22s ease;box-shadow:0 24px 60px rgba(0,0,0,.22);
}
@keyframes slideUp{from{transform:translateY(20px);opacity:0}to{transform:none;opacity:1}}
.modal-head{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.modal-head h3{font-size:.98rem;font-weight:700}
.modal-x{background:none;border:none;font-size:1.25rem;cursor:pointer;color:var(--muted);line-height:1;padding:2px 6px;border-radius:6px}
.modal-x:hover{background:var(--surface);color:var(--text)}
.modal-body{padding:22px}
.modal-foot{padding:14px 22px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px}

/* ═══ Testimonial Card ═══════════════════════════════════════ */
.tm-card{border:1.5px solid var(--border);border-radius:var(--r-lg);padding:16px 18px;margin-bottom:12px;background:white;box-shadow:var(--sh)}
.tm-card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.tm-author{display:flex;align-items:center;gap:10px}
.tm-av{width:38px;height:38px;border-radius:50%;color:white;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.9rem;flex-shrink:0}
.tm-name{font-size:.88rem;font-weight:700}
.tm-role{font-size:.75rem;color:var(--muted)}
.tm-text{font-size:.85rem;color:var(--muted);line-height:1.6;border-left:3px solid var(--blue-l);padding-left:10px;margin-top:4px}
.tm-stars{color:#facc15;font-size:.85rem;margin-top:6px}

/* ═══ Plan Card ══════════════════════════════════════════════ */
.plan-edit-card{border:1.5px solid var(--border);border-radius:var(--r-lg);padding:20px;margin-bottom:16px;background:white;box-shadow:var(--sh)}
.plan-edit-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.plan-edit-title{font-size:.95rem;font-weight:700;display:flex;align-items:center;gap:8px}

/* ═══ Responsive ═════════════════════════════════════════════ */
@media(max-width:900px){
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .form-row.c3{grid-template-columns:1fr 1fr}
}
@media(max-width:620px){
  .sidebar{display:none}
  .main,.topbar{margin-left:0}
  .stat-grid{grid-template-columns:1fr 1fr}
}
</style>
</head>
<body>

<?php if (!$loggedIn): ?>
<!-- ╔══════════════════════════════════╗ -->
<!-- ║          LOGIN  PAGE             ║ -->
<!-- ╚══════════════════════════════════╝ -->
<div class="login-bg">
  <div class="login-card">
    <div class="login-logo">
      <div class="login-icon">📚</div>
      <h1>EduKhmer Admin</h1>
      <p>ចូលប្រើប្រព័ន្ធគ្រប់គ្រងគេហទំព័រ</p>
    </div>

    <?php if ($flash['msg']): ?>
    <div class="alert alert-<?= $flash['type'] === 'error' ? 'error' : 'success' ?>">
      <?= e($flash['msg']) ?>
    </div>
    <?php endif; ?>

    <div class="login-hint">
      Default — ឈ្មោះ: <strong>admin</strong> &nbsp;|&nbsp; ពាក្យសម្ងាត់: <strong>Admin@1234</strong>
    </div>

    <form method="POST" action="admin.php" autocomplete="on">
      <input type="hidden" name="action" value="login">

      <div class="fg">
        <label>ឈ្មោះអ្នកប្រើ ឬ អ៊ីមែល</label>
        <input type="text" name="username" placeholder="admin" required autofocus value="<?= e($_POST['username'] ?? '') ?>">
      </div>
      <div class="fg">
        <label>ពាក្យសម្ងាត់</label>
        <input type="password" name="password" placeholder="••••••••" required>
      </div>

      <button type="submit" class="btn btn-blue btn-full" style="margin-top:6px">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
        ចូលគណនី
      </button>
    </form>
  </div>
</div>

<?php else: ?>
<!-- ╔══════════════════════════════════╗ -->
<!-- ║        ADMIN DASHBOARD           ║ -->
<!-- ╚══════════════════════════════════╝ -->

<?php
$tabTitles = [
  'dashboard'    => '🏠 ផ្ទាំងគ្រប់គ្រង',
  'users'        => '👥 អ្នកប្រើប្រាស់',
  'schools'      => '🏫 សាលារៀន',
  'classes'      => '📚 ថ្នាក់រៀន',
  'students'     => '👨‍🎓 សិស្ស',
  'subjects'     => '📖 មុខវិជ្ជា',
  'scores'       => '📊 ពិន្ទុ',
  'attendance'   => '✅ វត្តមាន',
  'hero'         => '🖼️ Hero Section',
  'features'     => '⚡ Feature Cards',
  'plans'        => '💳 ផែនការតម្លៃ',
  'testimonials' => '💬 មតិយោបល់',
  'footer'       => '🔗 Footer & Contact',
  'settings'     => '⚙️ ការកំណត់គណនី',
  'user_roles'   => '🏷️ ប្រភេទអ្នកប្រើប្រាស់',
];
?>

<div class="layout">

  <!-- ══ SIDEBAR ══════════════════════════════════════════════ -->
  <aside class="sidebar">
    <div class="sb-logo">
      <div class="sb-logo-icon">📚</div>
      <div>
        <div class="sb-logo-text">EduKhmer</div>
        <div class="sb-logo-sub">Admin Panel</div>
      </div>
    </div>

    <nav class="sb-nav">
      <div class="sb-sec">ទូទៅ</div>
      <a class="sb-item <?= $tab==='dashboard'?'active':'' ?>" href="?tab=dashboard">
        <span class="ico">🏠</span> ផ្ទាំងគ្រប់គ្រង
      </a>
      <a class="sb-item <?= $tab==='users'?'active':'' ?>" href="?tab=users">
        <span class="ico">👥</span> អ្នកប្រើប្រាស់
      </a>
      <a class="sb-item <?= $tab==='user_roles'?'active':'' ?>" href="?tab=user_roles">
        <span class="ico">🏷️</span> ប្រភេទអ្នកប្រើ
      </a>
      <a class="sb-item <?= $tab==='dash_categories'?'active':'' ?>" href="?tab=dash_categories">
        <span class="ico">⊞</span> ប្រភេទ Dashboard
      </a>

      <div class="sb-sec">គ្រប់គ្រងទិន្នន័យ</div>
      <a class="sb-item <?= $tab==='schools'?'active':'' ?>" href="?tab=schools">
        <span class="ico">🏫</span> សាលារៀន
      </a>
      <a class="sb-item <?= $tab==='classes'?'active':'' ?>" href="?tab=classes">
        <span class="ico">📚</span> ថ្នាក់រៀន
      </a>
      <a class="sb-item <?= $tab==='students'?'active':'' ?>" href="?tab=students">
        <span class="ico">👨‍🎓</span> សិស្ស
      </a>
      <a class="sb-item <?= $tab==='subjects'?'active':'' ?>" href="?tab=subjects">
        <span class="ico">📖</span> មុខវិជ្ជា
      </a>
      <a class="sb-item <?= $tab==='scores'?'active':'' ?>" href="?tab=scores">
        <span class="ico">📊</span> ពិន្ទុ
      </a>
      <a class="sb-item <?= $tab==='attendance'?'active':'' ?>" href="?tab=attendance">
        <span class="ico">✅</span> វត្តមាន
      </a>

      <div class="sb-sec">គ្រប់គ្រងខ្លឹមសារ</div>
      <a class="sb-item <?= $tab==='hero'?'active':'' ?>" href="?tab=hero">
        <span class="ico">🖼️</span> Hero Section
      </a>
      <a class="sb-item <?= $tab==='features'?'active':'' ?>" href="?tab=features">
        <span class="ico">⚡</span> Feature Cards
      </a>
      <a class="sb-item <?= $tab==='plans'?'active':'' ?>" href="?tab=plans">
        <span class="ico">💳</span> ផែនការតម្លៃ
      </a>
      <a class="sb-item <?= $tab==='testimonials'?'active':'' ?>" href="?tab=testimonials">
        <span class="ico">💬</span> មតិយោបល់
      </a>
      <a class="sb-item <?= $tab==='footer'?'active':'' ?>" href="?tab=footer">
        <span class="ico">🔗</span> Footer & Contact
      </a>

      <div class="sb-sec">ការកំណត់</div>
      <a class="sb-item <?= $tab==='settings'?'active':'' ?>" href="?tab=settings">
        <span class="ico">⚙️</span> ការកំណត់គណនី
      </a>
    </nav>

    <div class="sb-foot">
      <a class="sb-item" href="smsnew_author.html" target="_blank">
        <span class="ico">🌐</span> មើលគេហទំព័រ
      </a>
      <form method="POST" action="admin.php">
        <input type="hidden" name="action" value="logout">
        <button type="submit" class="sb-item" style="width:100%;border:none;background:none;cursor:pointer;color:rgba(255,255,255,.6)">
          <span class="ico">🚪</span> ចាកចេញ
        </button>
      </form>
    </div>
  </aside>

  <!-- ══ TOPBAR ════════════════════════════════════════════════ -->
  <header class="topbar">
    <div class="topbar-title"><?= $tabTitles[$tab] ?? 'Admin' ?></div>
    <div class="admin-pill">
      <div class="admin-av"><?= strtoupper(mb_substr($me['full_name'] ?? 'A', 0, 1)) ?></div>
      <div>
        <div class="admin-name"><?= e($me['full_name'] ?? 'Admin') ?></div>
        <div class="admin-role"><?= e($me['role'] ?? '') ?></div>
      </div>
    </div>
  </header>

  <!-- ══ MAIN ══════════════════════════════════════════════════ -->
  <div class="main">

    <?php if ($flash['msg']): ?>
    <div class="alert alert-<?= $flash['type'] === 'error' ? 'error' : 'success' ?>" id="flash"<?= !empty($flash['persist']) ? ' data-persist="1" style="position:relative;padding-right:40px"' : '' ?>>
      <?= $flash['msg'] ?>
      <?php if (!empty($flash['persist'])): ?>
      <button onclick="this.parentElement.remove()" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;font-size:1.1rem;cursor:pointer;color:inherit;opacity:.7;line-height:1">✕</button>
      <?php endif; ?>
    </div>
    <?php endif; ?>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: DASHBOARD                          -->
    <!-- ─────────────────────────────────────── -->
    <?php if ($tab === 'dashboard'): ?>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon" style="background:#dbeafe">👨‍🏫</div>
        <div><div class="stat-val"><?= $stats['users'] ?></div><div class="stat-lbl">អ្នកប្រើប្រាស់</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background:#dcfce7">👨‍🎓</div>
        <div><div class="stat-val"><?= $stats['students'] ?></div><div class="stat-lbl">សិស្ស</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background:#ede9fe">📚</div>
        <div><div class="stat-val"><?= $stats['classes'] ?></div><div class="stat-lbl">ថ្នាក់រៀន</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background:#ffedd5">🏫</div>
        <div><div class="stat-val"><?= $stats['schools'] ?></div><div class="stat-lbl">សាលារៀន</div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <h3>👥 អ្នកប្រើប្រាស់ចុះឈ្មោះថ្មីៗ</h3>
        <a href="?tab=users" class="btn btn-ghost btn-sm">មើលទាំងអស់ →</a>
      </div>
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>ឈ្មោះ</th><th>អ៊ីមែល</th><th>តួនាទី</th><th>ស្ថានភាព</th><th>ចុះឈ្មោះ</th></tr></thead>
          <tbody>
            <?php foreach ($recentUsers as $u): ?>
            <tr>
              <td style="color:var(--muted)"><?= $u['id'] ?></td>
              <td><strong><?= e($u['first_name'].' '.$u['last_name']) ?></strong></td>
              <td><?= e($u['email']) ?></td>
              <td><span class="badge b-blue"><?= e($u['role']) ?></span></td>
              <td><?= $u['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
              <td style="color:var(--muted)"><?= date('d M Y', strtotime($u['created_at'])) ?></td>
            </tr>
            <?php endforeach; ?>
            <?php if (!$recentUsers): ?>
            <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានអ្នកប្រើប្រាស់</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div class="card">
        <div class="card-head"><h3>🔗 ចូលទំព័រ</h3></div>
        <div class="card-body" style="display:flex;flex-direction:column;gap:8px">
          <?php foreach ([
            ['?tab=hero',         '🖼️','Hero & Announcement'],
            ['?tab=features',     '⚡','Feature Cards (6 cards)'],
            ['?tab=plans',        '💳','ផែនការតម្លៃ'],
            ['?tab=testimonials', '💬','មតិយោបល់'],
            ['?tab=footer',       '🔗','Footer Content'],
          ] as [$href,$ico,$lbl]): ?>
          <a href="<?= $href ?>" style="display:flex;align-items:center;gap:9px;padding:9px 12px;border:1px solid var(--border);border-radius:8px;font-size:.85rem;font-weight:600;color:var(--text);transition:all .15s" onmouseover="this.style.borderColor='var(--blue)';this.style.color='var(--blue)'" onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--text)'">
            <span><?= $ico ?></span><?= $lbl ?>
            <span style="margin-left:auto;color:var(--muted)">→</span>
          </a>
          <?php endforeach; ?>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>ℹ️ ព័ត៌មានប្រព័ន្ធ</h3></div>
        <div class="card-body" style="font-size:.85rem;color:var(--muted);display:flex;flex-direction:column;gap:6px">
          <div>🖥️ PHP <?= PHP_VERSION ?></div>
          <div>🗄️ MySQL Connected</div>
          <div>👤 Logged in: <strong style="color:var(--text)"><?= e($me['username']) ?></strong></div>
          <div>🕐 Session: <?= date('H:i') ?></div>
          <div>📅 Last login: <?= e($me['last_login'] ?? 'N/A') ?></div>
        </div>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: USERS                              -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'users'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>👥 អ្នកប្រើប្រាស់ (<?= count($users) ?>)</h2>
        <p>គ្រូបង្រៀន និង អ្នកប្រើប្រាស់ដែលបានចុះឈ្មោះ</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mUser');resetUserModal()">
        + បន្ថែមអ្នកប្រើ
      </button>
    </div>

    <div class="card">
      <div class="card-body np">
        <table>
          <thead>
            <tr>
              <th>#</th><th>ឈ្មោះ</th><th>អ៊ីមែល</th><th>ទូរស័ព្ទ</th>
              <th>តួនាទី / ប្រភេទ</th><th>ស្ថានភាព</th><th>ចុះឈ្មោះ</th><th>សកម្មភាព</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
              <td style="color:var(--muted)"><?= $u['id'] ?></td>
              <td><strong><?= e($u['first_name'].' '.$u['last_name']) ?></strong></td>
              <td><?= e($u['email']) ?></td>
              <td><?= e($u['phone'] ?: '—') ?></td>
              <td>
                <!-- Quick role/category changer -->
                <form method="POST" action="?tab=users" style="display:inline-flex;align-items:center;gap:5px">
                  <input type="hidden" name="action"  value="change_user_role">
                  <input type="hidden" name="csrf"    value="<?= e($csrf) ?>">
                  <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                  <select name="role" onchange="this.form.submit()" style="border:1.5px solid var(--border);border-radius:7px;padding:3px 8px;font-size:.77rem;font-family:inherit;cursor:pointer;background:white">
                    <?php foreach ($userRoles as $ur): ?>
                    <option value="<?= e($ur['slug']) ?>" <?= $u['role']===$ur['slug']?'selected':'' ?>><?= e($ur['icon'].' '.$ur['label']) ?></option>
                    <?php endforeach; ?>
                  </select>
                </form>
              </td>
              <td><?= $u['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
              <td style="color:var(--muted);font-size:.78rem"><?= date('d/m/Y', strtotime($u['created_at'])) ?></td>
              <td>
                <div class="td-actions">
                  <button class="btn btn-ghost btn-sm" onclick='editUser(<?= htmlspecialchars(json_encode($u), ENT_QUOTES) ?>)'>✏️ កែ</button>
                  <form method="POST" action="?tab=users" onsubmit="return confirm('លុបអ្នកប្រើប្រាស់នេះ?')">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="csrf"    value="<?= e($csrf) ?>">
                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                    <button type="submit" class="btn btn-red btn-sm">🗑️ លុប</button>
                  </form>
                </div>
              </td>
            </tr>
            <?php endforeach; ?>
            <?php if (!$users): ?>
            <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានអ្នកប្រើ</td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── Credential Log ─────────────────────────────────── -->
    <div class="card" style="margin-top:20px">
      <div class="card-head" style="background:linear-gradient(135deg,#1a2340,#0054a6);color:white;border-radius:var(--r) var(--r) 0 0">
        <h3 style="color:white">🔐 កំណត់ហេតុព័ត៌មានចូល (Credential Log) — <?= count($credLogs) ?> គណនី</h3>
        <span style="font-size:.75rem;opacity:.8">រៀបចំដោយប្រព័ន្ធ · ចូលប្រើអ្នកគ្រប់គ្រងប៉ុណ្ណោះ</span>
      </div>
      <?php if ($credLogs): ?>
      <div style="overflow-x:auto">
        <table style="font-size:.82rem">
          <thead>
            <tr>
              <th style="width:36px">#</th>
              <th>ឈ្មោះ</th>
              <th>Username (Email)</th>
              <th>
                <span style="display:inline-flex;align-items:center;gap:5px">
                  🔑 Password
                  <button onclick="toggleAllPw(this)" style="background:rgba(0,84,166,.1);border:1px solid var(--border);border-radius:5px;padding:1px 7px;font-size:.7rem;cursor:pointer;color:var(--blue)">បង្ហាញ</button>
                </span>
              </th>
              <th>ទូរស័ព្ទ</th>
              <th>ប្រភេទ</th>
              <th>ប្រភព</th>
              <th>📅 កាលបរិច្ឆេទ</th>
              <th>ស្ថានភាព</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($credLogs as $i => $cl): ?>
          <tr style="<?= $cl['is_active']===0 ? 'opacity:.45' : '' ?>">
            <td style="color:var(--muted)"><?= $i+1 ?></td>
            <td>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="width:30px;height:30px;border-radius:50%;background:<?= ['#0054a6','#1b8a4c','#c2410c','#7c3aed','#db2777'][($cl['id']-1)%5] ?>;color:white;display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;flex-shrink:0">
                  <?= mb_strtoupper(mb_substr($cl['full_name'] ?? '?', 0, 1, 'UTF-8'), 'UTF-8') ?>
                </div>
                <strong><?= e($cl['full_name'] ?: ($cl['first_name'].' '.$cl['last_name'])) ?></strong>
              </div>
            </td>
            <td>
              <span style="font-family:monospace;font-size:.79rem;background:#f0f4ff;padding:2px 6px;border-radius:5px"><?= e($cl['username']) ?></span>
            </td>
            <td>
              <div style="display:inline-flex;align-items:center;gap:6px">
                <span class="pw-mask" style="font-family:monospace;font-size:.82rem;letter-spacing:2px;color:var(--muted)">••••••••</span>
                <span class="pw-plain" style="display:none;font-family:monospace;font-size:.82rem;background:#fff8e1;padding:2px 6px;border-radius:5px;border:1px solid #f59e0b;color:#92400e"><?= e($cl['plain_pass']) ?></span>
                <button class="pw-btn" onclick="togglePw(this)" style="background:none;border:1px solid var(--border);border-radius:5px;padding:1px 6px;font-size:.68rem;cursor:pointer;color:var(--blue)">👁</button>
              </div>
            </td>
            <td style="color:var(--muted)"><?= e($cl['phone'] ?: '—') ?></td>
            <td><span class="badge b-blue" style="font-size:.68rem"><?= e($cl['role'] ?: 'teacher') ?></span></td>
            <td>
              <?php if ($cl['source']==='admin'): ?>
                <span class="badge b-orange" style="font-size:.68rem">👨‍💼 Admin</span>
              <?php else: ?>
                <span class="badge b-green" style="font-size:.68rem">🌐 Self</span>
              <?php endif; ?>
            </td>
            <td style="white-space:nowrap;color:var(--muted);font-size:.78rem">
              <?= date('d/m/Y', strtotime($cl['registered_at'])) ?><br>
              <span style="font-size:.7rem"><?= date('H:i:s', strtotime($cl['registered_at'])) ?></span>
            </td>
            <td>
              <?php if ($cl['is_active'] === null): ?>
                <span class="badge b-muted" style="font-size:.68rem">លុបហើយ</span>
              <?php elseif ($cl['is_active']): ?>
                <span class="badge b-green" style="font-size:.68rem">សកម្ម</span>
              <?php else: ?>
                <span class="badge b-red" style="font-size:.68rem">អសកម្ម</span>
              <?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?>
      <div class="card-body" style="text-align:center;color:var(--muted);padding:40px">
        <div style="font-size:2.5rem;margin-bottom:12px">🔐</div>
        <p>មិនទាន់មានគណនីណាមួយ — នឹងបង្ហាញនៅពេលអ្នកប្រើចុះឈ្មោះ ឬ Admin បន្ថែមគណនី</p>
      </div>
      <?php endif; ?>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: SCHOOLS                            -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'schools'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>🏫 សាលារៀន (<?= count($schools) ?>)</h2>
        <p>គ្រប់គ្រងទិន្នន័យសាលារៀន</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mSchool');resetSchoolModal()">+ បន្ថែមសាលា</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>ឈ្មោះ</th><th>ខេត្ត/ក្រុង</th><th>ទូរស័ព្ទ</th><th>អ៊ីមែល</th><th>ស្ថានភាព</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php foreach ($schools as $s): ?>
          <tr>
            <td style="color:var(--muted)"><?= $s['id'] ?></td>
            <td><strong><?= e($s['name']) ?></strong><?php if($s['address']): ?><br><small style="color:var(--muted)"><?= e(mb_substr($s['address'],0,50)) ?></small><?php endif; ?></td>
            <td><?= e($s['province'] ?: '—') ?></td>
            <td><?= e($s['phone'] ?: '—') ?></td>
            <td><?= e($s['email'] ?: '—') ?></td>
            <td><?= $s['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editSchool(<?= htmlspecialchars(json_encode($s), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=schools" onsubmit="return confirm('លុបសាលានេះ?')">
                  <input type="hidden" name="action" value="delete_school">
                  <input type="hidden" name="csrf"     value="<?= e($csrf) ?>">
                  <input type="hidden" name="school_id" value="<?= $s['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$schools): ?><tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានសាលារៀន</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: CLASSES                            -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'classes'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>📚 ថ្នាក់រៀន (<?= count($classes) ?>)</h2>
        <p>គ្រប់គ្រងថ្នាក់រៀន ភ្ជាប់ជាមួយសាលា និងគ្រូ</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mClass');resetClassModal()">+ បន្ថែមថ្នាក់</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>ឈ្មោះថ្នាក់</th><th>ថ្នាក់ទី</th><th>ឆ្នាំសិក្សា</th><th>សាលា</th><th>គ្រូ</th><th>ស្ថានភាព</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php foreach ($classes as $c): ?>
          <tr>
            <td style="color:var(--muted)"><?= $c['id'] ?></td>
            <td><strong><?= e($c['name']) ?></strong></td>
            <td><?= e($c['grade'] ?: '—') ?></td>
            <td><?= e($c['academic_year'] ?: '—') ?></td>
            <td><?= e($c['school_name'] ?: '—') ?></td>
            <td><?= e($c['teacher_name'] ?: '—') ?></td>
            <td><?= $c['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editClass(<?= htmlspecialchars(json_encode($c), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=classes" onsubmit="return confirm('លុបថ្នាក់នេះ?')">
                  <input type="hidden" name="action"   value="delete_class">
                  <input type="hidden" name="csrf"     value="<?= e($csrf) ?>">
                  <input type="hidden" name="class_id" value="<?= $c['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$classes): ?><tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានថ្នាក់រៀន</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: STUDENTS                           -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'students'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>👨‍🎓 សិស្ស (<?= count($students) ?>)</h2>
        <p>គ្រប់គ្រងទិន្នន័យសិស្សសរុប</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mStudent');resetStudentModal()">+ បន្ថែមសិស្ស</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>លេខកូដ</th><th>ឈ្មោះ</th><th>ភេទ</th><th>ថ្ងៃខែឆ្នាំកំណើត</th><th>ថ្នាក់</th><th>ទូរស័ព្ទ(មាតាបិតា)</th><th>ស្ថានភាព</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php foreach ($students as $s): ?>
          <tr>
            <td style="color:var(--muted)"><?= $s['id'] ?></td>
            <td><span class="badge b-muted"><?= e($s['student_code'] ?: '—') ?></span></td>
            <td><strong><?= e($s['first_name'].' '.$s['last_name']) ?></strong></td>
            <td><?= $s['gender'] === 'male' ? '♂' : ($s['gender'] === 'female' ? '♀' : '—') ?></td>
            <td style="font-size:.78rem;color:var(--muted)"><?= $s['dob'] ? date('d/m/Y', strtotime($s['dob'])) : '—' ?></td>
            <td><?= e($s['class_name'] ?: '—') ?></td>
            <td><?= e($s['parent_phone'] ?: '—') ?></td>
            <td><?= $s['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editStudent(<?= htmlspecialchars(json_encode($s), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=students" onsubmit="return confirm('លុបសិស្សនេះ?')">
                  <input type="hidden" name="action"     value="delete_student">
                  <input type="hidden" name="csrf"       value="<?= e($csrf) ?>">
                  <input type="hidden" name="student_id" value="<?= $s['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$students): ?><tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានសិស្ស</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: SUBJECTS                           -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'subjects'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>📖 មុខវិជ្ជា (<?= count($subjects) ?>)</h2>
        <p>គ្រប់គ្រងមុខវិជ្ជាបង្រៀន</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mSubject');resetSubjectModal()">+ បន្ថែមមុខវិជ្ជា</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>ឈ្មោះ</th><th>លេខកូដ</th><th>ការពិពណ៌នា</th><th>ស្ថានភាព</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php foreach ($subjects as $s): ?>
          <tr>
            <td style="color:var(--muted)"><?= $s['id'] ?></td>
            <td><strong><?= e($s['name']) ?></strong></td>
            <td><span class="badge b-muted"><?= e($s['code'] ?: '—') ?></span></td>
            <td style="color:var(--muted);font-size:.81rem"><?= e(mb_substr($s['description'] ?? '',0,60)) ?: '—' ?></td>
            <td><?= $s['is_active'] ? '<span class="badge b-green">សកម្ម</span>' : '<span class="badge b-red">អសកម្ម</span>' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editSubject(<?= htmlspecialchars(json_encode($s), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=subjects" onsubmit="return confirm('លុបមុខវិជ្ជានេះ?')">
                  <input type="hidden" name="action"     value="delete_subject">
                  <input type="hidden" name="csrf"       value="<?= e($csrf) ?>">
                  <input type="hidden" name="subject_id" value="<?= $s['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$subjects): ?><tr><td colspan="6" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានមុខវិជ្ជា</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: SCORES                             -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'scores'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>📊 ពិន្ទុ (<?= count($scores) ?>)</h2>
        <p>គ្រប់គ្រងពិន្ទុសិស្ស — បន្ថែម / កែ / លុប</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mScore');resetScoreModal()">+ បន្ថែមពិន្ទុ</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>សិស្ស</th><th>មុខវិជ្ជា</th><th>ប្រភេទ</th><th>ពិន្ទុ</th><th>ពិន្ទុស្ដង់ដារ</th><th>ថ្ងៃ</th><th>ចំណាំ</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php foreach ($scores as $sc): ?>
          <?php $pct = $sc['max_score'] > 0 ? round($sc['score']/$sc['max_score']*100) : 0; ?>
          <tr>
            <td style="color:var(--muted)"><?= $sc['id'] ?></td>
            <td><strong><?= e($sc['student_name'] ?: '#'.$sc['student_id']) ?></strong></td>
            <td><?= e($sc['subject_name'] ?: '#'.$sc['subject_id']) ?></td>
            <td><span class="badge b-muted"><?= e($sc['score_type']) ?></span></td>
            <td><strong style="color:<?= $pct>=70?'var(--green)':($pct>=50?'var(--accent)':'var(--red)') ?>"><?= $sc['score'] ?></strong></td>
            <td style="color:var(--muted)"><?= $sc['max_score'] ?></td>
            <td style="font-size:.78rem;color:var(--muted)"><?= $sc['scored_at'] ? date('d/m/Y', strtotime($sc['scored_at'])) : '—' ?></td>
            <td style="font-size:.78rem;color:var(--muted)"><?= e(mb_substr($sc['note']??'',0,30)) ?: '—' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editScore(<?= htmlspecialchars(json_encode($sc), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=scores" onsubmit="return confirm('លុបពិន្ទុនេះ?')">
                  <input type="hidden" name="action"   value="delete_score">
                  <input type="hidden" name="csrf"     value="<?= e($csrf) ?>">
                  <input type="hidden" name="score_id" value="<?= $sc['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$scores): ?><tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានពិន្ទុ</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: ATTENDANCE                         -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'attendance'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>✅ វត្តមាន (<?= count($attendance) ?>)</h2>
        <p>គ្រប់គ្រងការចុះវត្តមានសិស្ស</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mAttendance');resetAttModal()">+ បន្ថែមវត្តមាន</button>
    </div>
    <div class="card">
      <div class="card-body np">
        <table>
          <thead><tr><th>#</th><th>សិស្ស</th><th>ថ្នាក់</th><th>ថ្ងៃ</th><th>ស្ថានភាព</th><th>ចំណាំ</th><th>សកម្មភាព</th></tr></thead>
          <tbody>
          <?php
          $attColors = ['present'=>'b-green','absent'=>'b-red','late'=>'b-orange','excused'=>'b-muted'];
          $attLabels = ['present'=>'វត្តមាន','absent'=>'អវត្តមាន','late'=>'យឺត','excused'=>'មានច្បាប់'];
          foreach ($attendance as $a): ?>
          <tr>
            <td style="color:var(--muted)"><?= $a['id'] ?></td>
            <td><strong><?= e($a['student_name'] ?: '#'.$a['student_id']) ?></strong></td>
            <td><?= e($a['class_name'] ?: '—') ?></td>
            <td><?= date('d/m/Y', strtotime($a['attend_date'])) ?></td>
            <td><span class="badge <?= $attColors[$a['status']] ?? 'b-muted' ?>"><?= $attLabels[$a['status']] ?? $a['status'] ?></span></td>
            <td style="font-size:.78rem;color:var(--muted)"><?= e(mb_substr($a['note']??'',0,30)) ?: '—' ?></td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='editAtt(<?= htmlspecialchars(json_encode($a), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=attendance" onsubmit="return confirm('លុបកំណត់ត្រានេះ?')">
                  <input type="hidden" name="action" value="delete_attendance">
                  <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
                  <input type="hidden" name="att_id" value="<?= $a['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$attendance): ?><tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មានវត្តមាន</td></tr><?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: HERO SECTION                       -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'hero'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>🖼️ Hero Section</h2>
        <p>កែប្រែអត្ថបទ Banner ដំបូង, ស្ថិតិ, និង Announcement bar</p>
      </div>
    </div>

    <?php
    $heroSections = [
      'Announcement Bar' => [
        'announcement' => 'Announcement Text',
      ],
      'Hero Headline' => [
        'hero_badge_text' => 'Badge Text (ក្រោម Nav)',
        'hero_title'      => 'Hero Title ធំ',
        'hero_subtitle'   => 'Hero Description',
      ],
      'Hero Statistics' => [
        'stat_teachers'   => 'ចំនួនគ្រូ (ឧ. 5,000+)',
        'stat_schools'    => 'ចំនួនសាលា (ឧ. 120+)',
        'stat_satisfaction'=> 'ការពេញចិត្ត (ឧ. 98%)',
      ],
      'How It Works Section' => [
        'how_section_label'   => 'Section Label',
        'how_section_title'   => 'Section Title',
        'how_section_sub'     => 'Section Subtitle',
        'how_step1_title'     => 'ជំហាន 1 — ចំណងជើង',
        'how_step1_desc'      => 'ជំហាន 1 — ការពិពណ៌នា',
        'how_step2_title'     => 'ជំហាន 2 — ចំណងជើង',
        'how_step2_desc'      => 'ជំហាន 2 — ការពិពណ៌នា',
        'how_step3_title'     => 'ជំហាន 3 — ចំណងជើង',
        'how_step3_desc'      => 'ជំហាន 3 — ការពិពណ៌នា',
      ],
      'CTA Banner' => [
        'cta_title'  => 'CTA Banner Title',
        'cta_desc'   => 'CTA Banner Description',
        'cta_btn1'   => 'CTA Button 1 Text',
        'cta_btn2'   => 'CTA Button 2 Text',
      ],
    ];
    foreach ($heroSections as $secName => $fields): ?>

    <div class="card">
      <div class="card-head"><h3><?= e($secName) ?></h3></div>
      <div class="card-body">
        <form method="POST" action="?tab=hero">
          <input type="hidden" name="action" value="save_content_bulk">
          <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
          <?php foreach ($fields as $key => $label): $val = $cv($key); ?>
          <div class="field-row">
            <div class="field-row-inner">
              <label><?= e($label) ?><small style="margin-left:6px;font-weight:400;color:#aaa">[<?= e($key) ?>]</small></label>
              <input type="hidden" name="pairs[<?= e($key) ?>]" id="hf_<?= $key ?>_hidden">
              <?php if (mb_strlen($val) > 80 || strpos($key,'desc') !== false || strpos($key,'sub') !== false): ?>
              <textarea name="pairs[<?= e($key) ?>]" rows="2"><?= e($val) ?></textarea>
              <?php else: ?>
              <input type="text" name="pairs[<?= e($key) ?>]" value="<?= e($val) ?>">
              <?php endif; ?>
            </div>
          </div>
          <?php endforeach; ?>
          <div style="margin-top:14px;text-align:right">
            <button type="submit" class="btn btn-blue">💾 រក្សាទុក <?= e($secName) ?></button>
          </div>
        </form>
      </div>
    </div>

    <?php endforeach; ?>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: FEATURE CARDS                      -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'features'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>⚡ Feature Cards</h2>
        <p>កែប្រែ 6 Feature Cards ដែលបង្ហាញក្នុង Features Section</p>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
    <?php foreach ($siteFeatures as $feat): ?>
    <div class="card">
      <div class="card-head">
        <h3>Feature <?= $feat['sort_order'] ?> — <?= e(mb_substr($feat['title'],0,22)) ?><?= mb_strlen($feat['title'])>22?'…':'' ?></h3>
        <span class="badge b-<?= $feat['is_active'] ? 'green' : 'red' ?>"><?= $feat['is_active']?'Show':'Hide' ?></span>
      </div>
      <div class="card-body">
        <form method="POST" action="?tab=features">
          <input type="hidden" name="action"  value="save_feature">
          <input type="hidden" name="csrf"    value="<?= e($csrf) ?>">
          <input type="hidden" name="feat_id" value="<?= $feat['id'] ?>">
          <div class="fg"><label>ចំណងជើង (Title)</label>
            <input type="text" name="title" value="<?= e($feat['title']) ?>"></div>
          <div class="fg"><label>ការពិពណ៌នា (Description)</label>
            <textarea name="desc" rows="3"><?= e($feat['description']) ?></textarea></div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-top:4px">
            <label class="chk"><input type="checkbox" name="is_active" <?= $feat['is_active']?'checked':'' ?>> បង្ហាញ</label>
            <button type="submit" class="btn-save">💾 រក្សាទុក</button>
          </div>
        </form>
      </div>
    </div>
    <?php endforeach; ?>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: PLANS                              -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'plans'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>💳 ផែនការតម្លៃ</h2>
        <p>កែប្រែ ឈ្មោះ តម្លៃ លក្ខណៈពិសេស និង CTA Button</p>
      </div>
    </div>

    <?php foreach ($plans as $p):
      $featArr  = json_decode($p['features'] ?? '[]', true) ?: [];
      $featText = implode("\n", $featArr);
    ?>
    <div class="plan-edit-card">
      <div class="plan-edit-head">
        <div class="plan-edit-title">
          <?= e($p['name']) ?>
          <?php if ($p['is_featured']): ?><span class="badge b-orange">⭐ Featured</span><?php endif; ?>
        </div>
        <span style="font-size:.8rem;color:var(--muted)"><?= e($p['plan_key']) ?></span>
      </div>
      <form method="POST" action="?tab=plans">
        <input type="hidden" name="action"  value="save_plan">
        <input type="hidden" name="csrf"    value="<?= e($csrf) ?>">
        <input type="hidden" name="plan_id" value="<?= $p['id'] ?>">
        <div class="form-row">
          <div class="fg"><label>ឈ្មោះផែនការ</label>
            <input type="text" name="name" value="<?= e($p['name']) ?>"></div>
          <div class="fg"><label>ចំណងជើងរង</label>
            <input type="text" name="subtitle" value="<?= e($p['subtitle'] ?? '') ?>"></div>
        </div>
        <div class="form-row c3">
          <div class="fg"><label>តម្លៃ (ឧ. $9)</label>
            <input type="text" name="price" value="<?= e($p['price']) ?>"></div>
          <div class="fg"><label>រយៈពេល (ឧ. / ខែ)</label>
            <input type="text" name="period" value="<?= e($p['period']) ?>"></div>
          <div class="fg"><label>CTA Button Label</label>
            <input type="text" name="cta_label" value="<?= e($p['cta_label'] ?? '') ?>"></div>
        </div>
        <div class="fg">
          <label>Features — ​មួយ Feature ក្នុងមួយ Line</label>
          <textarea name="features" rows="6"><?= e($featText) ?></textarea>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <label class="chk"><input type="checkbox" name="is_featured" <?= $p['is_featured']?'checked':'' ?>> ⭐ Featured / ណែនាំ</label>
          <button type="submit" class="btn btn-blue">💾 រក្សាទុក</button>
        </div>
      </form>
    </div>
    <?php endforeach; ?>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: TESTIMONIALS                       -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'testimonials'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>💬 មតិយោបល់</h2>
        <p>គ្រប់គ្រង Testimonial Cards ដែលបង្ហាញក្នុងគេហទំព័រ</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mTm');resetTmModal()">+ បន្ថែមមតិ</button>
    </div>

    <?php foreach ($testimonials as $t): ?>
    <div class="tm-card">
      <div class="tm-card-head">
        <div class="tm-author">
          <div class="tm-av" style="background:<?= e($t['avatar_color']) ?>"><?= mb_strtoupper(mb_substr($t['author_name'],0,1)) ?></div>
          <div>
            <div class="tm-name"><?= e($t['author_name']) ?></div>
            <div class="tm-role"><?= e($t['author_role']) ?></div>
          </div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <?= $t['is_active'] ? '<span class="badge b-green">បង្ហាញ</span>' : '<span class="badge b-red">លាក់</span>' ?>
          <button class="btn btn-ghost btn-sm" onclick='editTm(<?= htmlspecialchars(json_encode($t), ENT_QUOTES) ?>)'>✏️ កែ</button>
          <form method="POST" action="?tab=testimonials" onsubmit="return confirm('លុបមតិ?')" style="display:inline">
            <input type="hidden" name="action" value="delete_testimonial">
            <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
            <input type="hidden" name="t_id"   value="<?= $t['id'] ?>">
            <button type="submit" class="btn btn-red btn-sm">🗑️</button>
          </form>
        </div>
      </div>
      <div class="tm-stars"><?= str_repeat('★', (int)$t['stars']) ?><?= str_repeat('☆', 5-(int)$t['stars']) ?></div>
      <div class="tm-text"><?= e($t['content']) ?></div>
    </div>
    <?php endforeach; ?>
    <?php if (!$testimonials): ?>
    <div style="text-align:center;color:var(--muted);padding:40px;background:white;border-radius:var(--r-lg)">
      មិនទាន់មានមតិយោបល់ — <a href="#" onclick="openModal('mTm');resetTmModal();return false" style="color:var(--blue)">បន្ថែមថ្មី</a>
    </div>
    <?php endif; ?>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: FOOTER                             -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'footer'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>🔗 Footer & Contact</h2>
        <p>ព័ត៌មាន Footer, Social Links, ទំព័រ Contact</p>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h3>🔗 Footer Content</h3></div>
      <div class="card-body">
        <form method="POST" action="?tab=footer">
          <input type="hidden" name="action" value="save_content_bulk">
          <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
          <?php
          $footerFields = [
            'footer_description' => 'ការពិពណ៌នា Footer',
            'footer_facebook_url'=> 'Facebook URL',
            'footer_telegram_url'=> 'Telegram URL',
            'footer_youtube_url' => 'YouTube URL',
            'footer_email'       => 'Contact Email',
            'footer_phone'       => 'Contact Phone',
            'footer_address'     => 'Address',
            'footer_copyright'   => 'Copyright Text',
          ];
          foreach ($footerFields as $key => $label): $val = $cv($key); ?>
          <div class="field-row">
            <div class="field-row-inner">
              <label><?= e($label) ?> <small style="color:#aaa;font-weight:400">[<?= $key ?>]</small></label>
              <?php if (strpos($key,'address')!==false || strpos($key,'description')!==false): ?>
              <textarea name="pairs[<?= e($key) ?>]" rows="2"><?= e($val) ?></textarea>
              <?php else: ?>
              <input type="text" name="pairs[<?= e($key) ?>]" value="<?= e($val) ?>">
              <?php endif; ?>
            </div>
          </div>
          <?php endforeach; ?>
          <div style="margin-top:16px;text-align:right">
            <button type="submit" class="btn btn-blue">💾 រក្សាទុក Footer</button>
          </div>
        </form>
      </div>
    </div>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: SETTINGS                           -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'settings'): ?>

    <div class="sec-head"><div class="sec-head-left"><h2>⚙️ ការកំណត់គណនីអ្នកគ្រប់គ្រង</h2></div></div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start">

      <div class="card">
        <div class="card-head"><h3>🔒 ប្ដូរពាក្យសម្ងាត់</h3></div>
        <div class="card-body">
          <form method="POST" action="?tab=settings">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
            <div class="fg"><label>ពាក្យសម្ងាត់បច្ចុប្បន្ន</label>
              <input type="password" name="current_pass" required></div>
            <div class="fg"><label>ពាក្យសម្ងាត់ថ្មី (≥ 8 តួ)</label>
              <input type="password" name="new_pass" required></div>
            <div class="fg"><label>បញ្ជាក់ពាក្យសម្ងាត់ថ្មី</label>
              <input type="password" name="confirm_pass" required></div>
            <button type="submit" class="btn btn-blue btn-full">🔒 ប្ដូរពាក្យសម្ងាត់</button>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h3>👤 ព័ត៌មានគណនី</h3></div>
        <div class="card-body" style="font-size:.88rem;display:flex;flex-direction:column;gap:10px">
          <?php foreach ([
            ['ឈ្មោះ', $me['full_name']],
            ['ឈ្មោះអ្នកប្រើ', $me['username']],
            ['អ៊ីមែល', $me['email']],
            ['ចូលប្រើចុងក្រោយ', $me['last_login'] ?: 'N/A'],
          ] as [$lbl, $val]): ?>
          <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
            <span style="color:var(--muted)"><?= e($lbl) ?></span>
            <strong><?= e($val) ?></strong>
          </div>
          <?php endforeach; ?>
          <div style="display:flex;justify-content:space-between;padding:8px 0">
            <span style="color:var(--muted)">តួនាទី</span>
            <span class="badge b-orange"><?= e($me['role']) ?></span>
          </div>
        </div>
      </div>

    </div>

    <?php elseif ($tab === 'user_roles'): ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>🏷️ ប្រភេទអ្នកប្រើប្រាស់ (<?= count($userRoles) ?>)</h2>
        <p>បន្ថែម / កែ / លុប ប្រភេទ (Category) — ការផ្លាស់ប្ដូរនឹងបង្ហាញភ្លាមៗក្នុងគ្រប់ Dropdown</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openModal('mRole');resetRoleModal()">+ បន្ថែមប្រភេទ</button>
    </div>

    <!-- Icon category grid -->
    <div class="card" style="margin-bottom:22px">
      <div class="card-body" style="padding:20px">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:14px">
          <?php foreach ($userRoles as $ur):
              $uCount = $pdo->query("SELECT COUNT(*) FROM users WHERE role='".addslashes($ur['slug'])."'")->fetchColumn();
              $colors = [
                  'b-blue'   => ['bg'=>'#e8f0fb','ico'=>'#0054a6','bd'=>'#bed2f0'],
                  'b-green'  => ['bg'=>'#e8f5ee','ico'=>'#1b8a4c','bd'=>'#b7dfca'],
                  'b-orange' => ['bg'=>'#fff3e8','ico'=>'#c2410c','bd'=>'#fcd6a4'],
                  'b-red'    => ['bg'=>'#fdecea','ico'=>'#e53935','bd'=>'#f9bcba'],
                  'b-muted'  => ['bg'=>'#f1f5f9','ico'=>'#5a6475','bd'=>'#d1d9e6'],
              ];
              $cl = $colors[$ur['color']] ?? $colors['b-blue'];
          ?>
          <div style="background:<?= $cl['bg'] ?>;border:1.5px solid <?= $cl['bd'] ?>;border-radius:14px;padding:16px 10px 12px;text-align:center;position:relative;transition:box-shadow .2s" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,.1)'" onmouseout="this.style.boxShadow='none'">
            <!-- action buttons top-right -->
            <div style="position:absolute;top:7px;right:7px;display:flex;gap:3px">
              <button onclick='editRole(<?= htmlspecialchars(json_encode($ur),ENT_QUOTES) ?>)' title="កែ" style="background:white;border:1px solid <?= $cl['bd'] ?>;border-radius:6px;width:22px;height:22px;cursor:pointer;font-size:.7rem;display:flex;align-items:center;justify-content:center;color:<?= $cl['ico'] ?>">✏️</button>
              <?php if ($uCount == 0): ?>
              <form method="POST" action="?tab=user_roles" onsubmit="return confirm('លុបប្រភេទ «<?= e($ur['label']) ?>»?')" style="margin:0">
                <input type="hidden" name="action"    value="delete_user_role">
                <input type="hidden" name="csrf"      value="<?= e($csrf) ?>">
                <input type="hidden" name="role_id"   value="<?= $ur['id'] ?>">
                <input type="hidden" name="role_slug" value="<?= e($ur['slug']) ?>">
                <button type="submit" title="លុប" style="background:white;border:1px solid #f9bcba;border-radius:6px;width:22px;height:22px;cursor:pointer;font-size:.7rem;display:flex;align-items:center;justify-content:center;color:#e53935">🗑</button>
              </form>
              <?php else: ?>
              <button disabled title="មិនអាចលុប — មានអ្នកប្រើ <?= $uCount ?> នាក់" style="background:white;border:1px solid #ddd;border-radius:6px;width:22px;height:22px;cursor:not-allowed;font-size:.7rem;display:flex;align-items:center;justify-content:center;opacity:.35">🗑</button>
              <?php endif; ?>
            </div>
            <!-- icon -->
            <div style="font-size:2rem;margin-bottom:7px;line-height:1"><?= e($ur['icon']) ?></div>
            <!-- label -->
            <div style="font-weight:700;font-size:.82rem;color:<?= $cl['ico'] ?>;margin-bottom:5px;word-break:break-word"><?= e($ur['label']) ?></div>
            <!-- slug -->
            <div style="font-size:.68rem;color:var(--muted);margin-bottom:6px;font-family:monospace"><?= e($ur['slug']) ?></div>
            <!-- user count badge -->
            <span class="badge <?= e($ur['color']) ?>" style="font-size:.68rem"><?= $uCount ?> នាក់</span>
          </div>
          <?php endforeach; ?>

          <!-- Add new tile -->
          <div onclick="openModal('mRole');resetRoleModal()" style="background:#f8fafc;border:2px dashed #c8d7ea;border-radius:14px;padding:16px 10px 12px;text-align:center;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;min-height:130px;transition:background .2s" onmouseover="this.style.background='#e8f0fb'" onmouseout="this.style.background='#f8fafc'">
            <div style="font-size:1.8rem;color:var(--blue);opacity:.6">＋</div>
            <div style="font-size:.78rem;color:var(--blue);font-weight:600">បន្ថែមប្រភេទ</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Bulk Reassign -->
    <?php if (count($userRoles) >= 2): ?>
    <div class="card">
      <div class="card-head"><h3>🔄 ផ្លាស់ប្ដូរប្រភេទជាដុំ (Bulk Reassign)</h3></div>
      <div class="card-body">
        <form method="POST" action="?tab=user_roles" onsubmit="return confirm('ផ្លាស់ប្ដូរអ្នកប្រើប្រាស់ទាំងអស់?')">
          <input type="hidden" name="action" value="bulk_reassign_role">
          <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
          <div class="form-row" style="align-items:flex-end">
            <div class="fg">
              <label>ពី ប្រភេទ (From)</label>
              <select name="from_role">
                <?php foreach ($userRoles as $ur): ?>
                <option value="<?= e($ur['slug']) ?>"><?= e($ur['icon'].' '.$ur['label']) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="fg">
              <label>ទៅ ប្រភេទ (To)</label>
              <select name="to_role">
                <?php foreach ($userRoles as $ur): ?>
                <option value="<?= e($ur['slug']) ?>"><?= e($ur['icon'].' '.$ur['label']) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="fg" style="flex:0 0 auto">
              <button type="submit" class="btn btn-blue">🔄 ផ្លាស់ប្ដូរ</button>
            </div>
          </div>
          <small style="color:var(--muted)">⚠️ នឹងផ្លាស់ប្ដូរអ្នកប្រើប្រាស់ <strong>ទាំងអស់</strong> ដែលមានប្រភេទ "From" ទៅ "To"</small>
        </form>
      </div>
    </div>
    <?php endif; ?>

    <!-- ─────────────────────────────────────── -->
    <!-- TAB: DASHBOARD CATEGORIES               -->
    <!-- ─────────────────────────────────────── -->
    <?php elseif ($tab === 'dash_categories'): ?>

    <?php
    // Define all available color themes matching smsnew_author.html
    $miColors = [
        'mi-blue'    => ['bg'=>'#dbeafe','label'=>'Blue'],
        'mi-purple'  => ['bg'=>'#ede9fe','label'=>'Purple'],
        'mi-orange'  => ['bg'=>'#ffedd5','label'=>'Orange'],
        'mi-pink'    => ['bg'=>'#fce7f3','label'=>'Pink'],
        'mi-green'   => ['bg'=>'#dcfce7','label'=>'Green'],
        'mi-teal'    => ['bg'=>'#ccfbf1','label'=>'Teal'],
        'mi-red'     => ['bg'=>'#fee2e2','label'=>'Red'],
        'mi-yellow'  => ['bg'=>'#fef9c3','label'=>'Yellow'],
        'mi-indigo'  => ['bg'=>'#e0e7ff','label'=>'Indigo'],
        'mi-cyan'    => ['bg'=>'#cffafe','label'=>'Cyan'],
        'mi-lime'    => ['bg'=>'#ecfccb','label'=>'Lime'],
        'mi-rose'    => ['bg'=>'#ffe4e6','label'=>'Rose'],
        'mi-sky'     => ['bg'=>'#e0f2fe','label'=>'Sky'],
        'mi-violet'  => ['bg'=>'#f5f3ff','label'=>'Violet'],
        'mi-amber'   => ['bg'=>'#fef3c7','label'=>'Amber'],
        'mi-slate'   => ['bg'=>'#f1f5f9','label'=>'Slate'],
        'mi-emerald' => ['bg'=>'#d1fae5','label'=>'Emerald'],
        'mi-fuchsia' => ['bg'=>'#fdf4ff','label'=>'Fuchsia'],
    ];
    ?>

    <div class="sec-head">
      <div class="sec-head-left">
        <h2>⊞ ប្រភេទ Dashboard (<?= count($dashCategories) ?>)</h2>
        <p>គ្រប់គ្រង icon tiles ដែលបង្ហាញក្នុង Dashboard របស់អ្នកប្រើ — បន្ថែម / កែ / លុប / បិទ/បើក</p>
      </div>
      <button class="btn btn-blue btn-sm" onclick="openDashCatModal(0)">+ បន្ថែម Tile</button>
    </div>

    <!-- Live preview grid -->
    <div class="card" style="margin-bottom:18px">
      <div class="card-head">
        <h3>👁️ Preview — ដូចដែលអ្នកប្រើឃើញ</h3>
        <span style="font-size:.78rem;color:var(--muted)">Grid 4 ជួរ · ចុចដើម្បីចំលង slug</span>
      </div>
      <div class="card-body" style="background:linear-gradient(160deg,#e8f0fb,#f0f4ff,#f7f9fc);border-radius:0 0 var(--r) var(--r)">
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;max-width:520px;margin:0 auto;padding:10px 0">
          <?php foreach ($dashCategories as $dc): if (!$dc['is_active']) continue;
              $bgc = $miColors[$dc['color']]['bg'] ?? '#dbeafe'; ?>
          <div style="background:white;border-radius:16px;padding:16px 8px 12px;display:flex;flex-direction:column;align-items:center;gap:8px;box-shadow:0 2px 8px rgba(0,84,166,.07);border:1px solid rgba(0,84,166,.06);opacity:1">
            <div style="width:50px;height:50px;border-radius:14px;background:<?= $bgc ?>;display:flex;align-items:center;justify-content:center;font-size:1.3rem"><?= e($dc['icon']) ?></div>
            <div style="font-size:.7rem;font-weight:600;color:#1a1a2e;text-align:center;line-height:1.35"><?= e($dc['label']) ?></div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>

    <!-- Management table -->
    <div class="card">
      <div class="card-head">
        <h3>📋 បញ្ជី Tile ទាំងអស់</h3>
        <span style="font-size:.78rem;color:var(--muted)">Active: <?= count(array_filter($dashCategories, fn($d)=>$d['is_active'])) ?> / <?= count($dashCategories) ?></span>
      </div>
      <div class="card-body np">
        <table>
          <thead>
            <tr>
              <th style="width:40px">#</th>
              <th>Icon & Preview</th>
              <th>ឈ្មោះ (Label)</th>
              <th>ពណ៌</th>
              <th style="width:60px">លំដាប់</th>
              <th>ស្ថានភាព</th>
              <th>សកម្មភាព</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach ($dashCategories as $dc):
              $bgc = $miColors[$dc['color']]['bg'] ?? '#dbeafe';
              $colorLabel = $miColors[$dc['color']]['label'] ?? $dc['color'];
          ?>
          <tr style="<?= !$dc['is_active'] ? 'opacity:.5' : '' ?>">
            <td style="color:var(--muted)"><?= $dc['id'] ?></td>
            <td>
              <div style="width:44px;height:44px;border-radius:12px;background:<?= $bgc ?>;display:inline-flex;align-items:center;justify-content:center;font-size:1.25rem"><?= e($dc['icon']) ?></div>
            </td>
            <td><strong><?= e($dc['label']) ?></strong></td>
            <td>
              <span style="display:inline-flex;align-items:center;gap:6px;font-size:.78rem">
                <span style="width:14px;height:14px;border-radius:4px;background:<?= $bgc ?>;border:1px solid rgba(0,0,0,.1);display:inline-block"></span>
                <?= e($colorLabel) ?>
              </span>
            </td>
            <td style="color:var(--muted);text-align:center"><?= $dc['sort_order'] ?></td>
            <td>
              <?php if ($dc['is_active']): ?>
                <span class="badge b-green">បង្ហាញ</span>
              <?php else: ?>
                <span class="badge b-muted">លាក់</span>
              <?php endif; ?>
            </td>
            <td>
              <div class="td-actions">
                <button class="btn btn-ghost btn-sm" onclick='openDashCatModal(<?= htmlspecialchars(json_encode($dc), ENT_QUOTES) ?>)'>✏️ កែ</button>
                <form method="POST" action="?tab=dash_categories" style="display:inline">
                  <input type="hidden" name="action" value="toggle_dash_cat">
                  <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
                  <input type="hidden" name="cat_id" value="<?= $dc['id'] ?>">
                  <button type="submit" class="btn btn-outline btn-sm"><?= $dc['is_active'] ? '🙈 លាក់' : '👁️ បង្ហាញ' ?></button>
                </form>
                <form method="POST" action="?tab=dash_categories" onsubmit="return confirm('លុប Tile នេះ?')">
                  <input type="hidden" name="action" value="delete_dash_cat">
                  <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
                  <input type="hidden" name="cat_id" value="<?= $dc['id'] ?>">
                  <button type="submit" class="btn btn-red btn-sm">🗑️</button>
                </form>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (!$dashCategories): ?>
          <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">មិនទាន់មាន Tile — <a href="#" onclick="openDashCatModal(0);return false" style="color:var(--blue)">បន្ថែម</a></td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <?php endif; // end tabs ?>

  </div><!-- /main -->
</div><!-- /layout -->

<!-- ╔══════════════════════════════════╗ -->
<!-- ║        MODALS                    ║ -->
<!-- ╚══════════════════════════════════╝ -->

<!-- User Modal -->
<div class="modal-bg" id="mUser" onclick="if(event.target===this)closeModal('mUser')">
  <div class="modal">
    <div class="modal-head">
      <h3 id="mUserTitle">👤 បន្ថែមអ្នកប្រើប្រាស់</h3>
      <button class="modal-x" onclick="closeModal('mUser')">✕</button>
    </div>
    <form method="POST" action="?tab=users">
      <div class="modal-body">
        <input type="hidden" name="action"  value="save_user">
        <input type="hidden" name="csrf"    value="<?= e($csrf) ?>">
        <input type="hidden" name="user_id" id="uId" value="0">
        <div class="form-row">
          <div class="fg"><label>នាមខ្លួន *</label><input type="text" name="first_name" id="uFn" required></div>
          <div class="fg"><label>នាមត្រកូល *</label><input type="text" name="last_name"  id="uLn" required></div>
        </div>
        <div class="fg"><label>អ៊ីមែល *</label><input type="email" name="email" id="uEm" required></div>
        <div class="fg"><label>ទូរស័ព្ទ</label><input type="text" name="phone" id="uPh" placeholder="0xx xxx xxx"></div>
        <div class="fg" id="uPassWrap">
          <label>ពាក្យសម្ងាត់ <small style="color:var(--muted)">(Default: EduKhmer@123)</small></label>
          <input type="password" name="password" id="uPw" placeholder="ទុកទំនេរ ដើម្បីប្រើ default">
        </div>
        <div class="form-row">
          <div class="fg"><label>តួនាទី</label>
            <select name="role" id="uRole">
              <?php foreach ($userRoles as $ur): ?>
              <option value="<?= e($ur['slug']) ?>"><?= e($ur['icon'].' '.$ur['label']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="fg" style="display:flex;align-items:flex-end;padding-bottom:6px">
            <label class="chk"><input type="checkbox" name="is_active" id="uAc" checked> សកម្ម</label>
          </div>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn btn-outline" onclick="closeModal('mUser')">បោះបង់</button>
        <button type="submit" class="btn btn-blue">💾 រក្សាទុក</button>
      </div>
    </form>
  </div>
</div>

<!-- Testimonial Modal -->
<div class="modal-bg" id="mTm" onclick="if(event.target===this)closeModal('mTm')">
  <div class="modal">
    <div class="modal-head">
      <h3 id="mTmTitle">💬 បន្ថែមមតិយោបល់</h3>
      <button class="modal-x" onclick="closeModal('mTm')">✕</button>
    </div>
    <form method="POST" action="?tab=testimonials">
      <div class="modal-body">
        <input type="hidden" name="action" value="save_testimonial">
        <input type="hidden" name="csrf"   value="<?= e($csrf) ?>">
        <input type="hidden" name="t_id"   id="tId" value="0">
        <div class="fg"><label>ឈ្មោះ *</label><input type="text" name="author_name" id="tNm" required></div>
        <div class="fg"><label>តួនាទី / សាលា</label><input type="text" name="author_role" id="tRl" placeholder="ឧ. គ្រូ — សាលា XYZ"></div>
        <div class="form-row">
          <div class="fg"><label>ពណ៌ Avatar</label><input type="color" name="avatar_color" id="tCl" value="#0054a6" style="height:40px;cursor:pointer"></div>
          <div class="fg"><label>⭐ ផ្កាយ (1–5)</label><input type="number" name="stars" id="tSt" min="1" max="5" value="5"></div>
        </div>
        <div class="fg"><label>មតិ *</label><textarea name="content" id="tCt" rows="4" required></textarea></div>
        <div class="form-row">
          <div class="fg"><label>លំដាប់ (Sort)</label><input type="number" name="sort_order" id="tSo" value="0" min="0"></div>
          <div class="fg" style="display:flex;align-items:flex-end;padding-bottom:6px">
            <label class="chk"><input type="checkbox" name="is_active" id="tAc" checked> បង្ហាញ</label>
          </div>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn btn-outline" onclick="closeModal('mTm')">បោះបង់</button>
        <button type="submit" class="btn btn-blue">💾 រក្សាទុក</button>
      </div>
    </form>
  </div>
</div>

<?php endif; // loggedIn ?>

<!-- Role Category Modal -->
<div class="modal-bg" id="mRole" onclick="if(event.target===this)closeModal('mRole')">
  <div class="modal">
    <div class="modal-head">
      <h3 id="mRoleTitle">🏷️ បន្ថែមប្រភេទអ្នកប្រើ</h3>
      <button class="modal-x" onclick="closeModal('mRole')">✕</button>
    </div>
    <form method="POST" action="?tab=user_roles">
      <div class="modal-body">
        <input type="hidden" name="action"  value="save_user_role">
        <input type="hidden" name="csrf"    value="<?= $loggedIn ? e($csrf) : '' ?>">
        <input type="hidden" name="role_id" id="rId" value="0">
        <div class="form-row">
          <div class="fg">
            <label>Slug * <small style="color:var(--muted)">(lowercase, no spaces)</small></label>
            <input type="text" name="role_slug" id="rSlug" required placeholder="ឧ. principal" pattern="[a-z0-9_]+">
          </div>
          <div class="fg">
            <label>ឈ្មោះ *</label>
            <input type="text" name="role_label" id="rLabel" required placeholder="ឧ. ប្រធានសាលា">
          </div>
        </div>
        <div class="form-row">
          <div class="fg">
            <label>Icon (Emoji)</label>
            <input type="text" name="role_icon" id="rIcon" value="👤" placeholder="ឧ. 🧑‍💼" maxlength="10">
          </div>
          <div class="fg">
            <label>Badge Color</label>
            <select name="role_color" id="rColor">
              <option value="b-blue">🔵 Blue</option>
              <option value="b-green">🟢 Green</option>
              <option value="b-orange">🟠 Orange</option>
              <option value="b-red">🔴 Red</option>
              <option value="b-muted">⚪ Muted</option>
            </select>
          </div>
        </div>
        <div class="fg">
          <label>Sort Order <small style="color:var(--muted)">(តូច = ដំបូង)</small></label>
          <input type="number" name="sort_order" id="rSort" value="0" min="0">
        </div>
        <div style="background:var(--blue-l);border-radius:8px;padding:10px 14px;font-size:.8rem;color:var(--muted);margin-top:4px">
          💡 Slug ត្រូវប្រើអក្សរ lowercase ជា unique key — ឧ. <code>teacher</code>, <code>principal</code>, <code>admin_staff</code>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn btn-outline" onclick="closeModal('mRole')">បោះបង់</button>
        <button type="submit" class="btn btn-blue">💾 រក្សាទុក</button>
      </div>
    </form>
  </div>
</div>

<!-- Dashboard Category Modal -->
<div class="modal-bg" id="mDashCat" onclick="if(event.target===this)closeModal('mDashCat')">
  <div class="modal" style="max-width:520px">
    <div class="modal-head">
      <h3 id="mDashCatTitle">⊞ បន្ថែម Tile ថ្មី</h3>
      <button class="modal-x" onclick="closeModal('mDashCat')">✕</button>
    </div>
    <form method="POST" action="?tab=dash_categories">
      <div class="modal-body">
        <input type="hidden" name="action" value="save_dash_cat">
        <input type="hidden" name="csrf"   value="<?= $loggedIn ? e($csrf) : '' ?>">
        <input type="hidden" name="cat_id" id="dcId" value="0">

        <!-- Live mini preview -->
        <div style="display:flex;justify-content:center;margin-bottom:16px">
          <div id="dcPreview" style="width:90px;height:90px;border-radius:18px;background:#dbeafe;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 14px rgba(0,84,166,.12)">
            <div id="dcPreviewIcon" style="font-size:1.8rem">📌</div>
            <div id="dcPreviewLabel" style="font-size:.6rem;font-weight:700;color:#1a1a2e;text-align:center;padding:0 6px;line-height:1.3;max-height:28px;overflow:hidden">Tile</div>
          </div>
        </div>

        <div class="form-row">
          <div class="fg">
            <label>Icon (Emoji) *</label>
            <input type="text" name="cat_icon" id="dcIcon" value="📌" maxlength="10" placeholder="ឧ. 👨‍🎓" oninput="document.getElementById('dcPreviewIcon').textContent=this.value||'📌'">
          </div>
          <div class="fg">
            <label>ឈ្មោះ Tile *</label>
            <input type="text" name="cat_label" id="dcLabel" required placeholder="ឧ. បញ្ចូលព័ត៌មានសិស្ស" oninput="document.getElementById('dcPreviewLabel').textContent=this.value||'Tile'">
          </div>
        </div>

        <div class="fg">
          <label>ពណ៌ Background</label>
          <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-top:6px" id="colorPicker">
            <?php
            $colorOpts = [
              'mi-blue'=>'#dbeafe','mi-purple'=>'#ede9fe','mi-orange'=>'#ffedd5',
              'mi-pink'=>'#fce7f3','mi-green'=>'#dcfce7','mi-teal'=>'#ccfbf1',
              'mi-red'=>'#fee2e2','mi-yellow'=>'#fef9c3','mi-indigo'=>'#e0e7ff',
              'mi-cyan'=>'#cffafe','mi-lime'=>'#ecfccb','mi-rose'=>'#ffe4e6',
              'mi-sky'=>'#e0f2fe','mi-violet'=>'#f5f3ff','mi-amber'=>'#fef3c7',
              'mi-slate'=>'#f1f5f9','mi-emerald'=>'#d1fae5','mi-fuchsia'=>'#fdf4ff',
            ];
            foreach ($colorOpts as $cls => $hex): ?>
            <div class="color-swatch" data-color="<?= $cls ?>" data-bg="<?= $hex ?>"
                 onclick="pickDashColor('<?= $cls ?>','<?= $hex ?>')"
                 title="<?= ucfirst(str_replace('mi-','',$cls)) ?>"
                 style="width:100%;aspect-ratio:1;border-radius:10px;background:<?= $hex ?>;border:2px solid transparent;cursor:pointer;transition:border-color .15s">
            </div>
            <?php endforeach; ?>
          </div>
          <input type="hidden" name="cat_color" id="dcColor" value="mi-blue">
        </div>

        <div class="form-row">
          <div class="fg">
            <label>Sort Order <small style="color:var(--muted)">(តូច = ដំបូង)</small></label>
            <input type="number" name="cat_sort" id="dcSort" value="0" min="0">
          </div>
          <div class="fg" style="display:flex;align-items:flex-end;padding-bottom:6px">
            <label class="chk"><input type="checkbox" name="is_active" id="dcActive" checked> បង្ហាញ</label>
          </div>
        </div>
      </div>
      <div class="modal-foot">
        <button type="button" class="btn btn-outline" onclick="closeModal('mDashCat')">បោះបង់</button>
        <button type="submit" class="btn btn-blue">💾 រក្សាទុក</button>
      </div>
    </form>
  </div>
</div>

<script>
/* ── Modal helpers ──────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); document.body.style.overflow='hidden'; }
function closeModal(id) { document.getElementById(id).classList.remove('open'); document.body.style.overflow=''; }
document.addEventListener('keydown', e => { if(e.key==='Escape') document.querySelectorAll('.modal-bg.open').forEach(m=>m.classList.remove('open')); });

/* ── User Modal ─────────────────────────────── */
function resetUserModal(){
  document.getElementById('mUserTitle').textContent = '👤 បន្ថែមអ្នកប្រើប្រាស់';
  ['uId','uFn','uLn','uEm','uPh','uPw'].forEach(id => document.getElementById(id).value = id==='uId'?'0':'');
  document.getElementById('uRole').value = 'teacher';
  document.getElementById('uAc').checked = true;
  document.getElementById('uPassWrap').style.display = '';
}
function editUser(u){
  document.getElementById('mUserTitle').textContent = '✏️ កែប្រែ — ' + u.first_name + ' ' + u.last_name;
  document.getElementById('uId').value  = u.id;
  document.getElementById('uFn').value  = u.first_name;
  document.getElementById('uLn').value  = u.last_name;
  document.getElementById('uEm').value  = u.email;
  document.getElementById('uPh').value  = u.phone || '';
  document.getElementById('uRole').value = u.role;
  document.getElementById('uAc').checked = u.is_active == 1;
  document.getElementById('uPassWrap').style.display = 'none'; // hide when editing
  openModal('mUser');
}

/* ── Testimonial Modal ──────────────────────── */
function resetTmModal(){
  document.getElementById('mTmTitle').textContent = '💬 បន្ថែមមតិយោបល់';
  document.getElementById('tId').value = '0';
  document.getElementById('tNm').value = '';
  document.getElementById('tRl').value = '';
  document.getElementById('tCl').value = '#0054a6';
  document.getElementById('tSt').value = '5';
  document.getElementById('tCt').value = '';
  document.getElementById('tSo').value = '0';
  document.getElementById('tAc').checked = true;
}
function editTm(t){
  document.getElementById('mTmTitle').textContent = '✏️ កែប្រែ — ' + t.author_name;
  document.getElementById('tId').value = t.id;
  document.getElementById('tNm').value = t.author_name;
  document.getElementById('tRl').value = t.author_role || '';
  document.getElementById('tCl').value = t.avatar_color || '#0054a6';
  document.getElementById('tSt').value = t.stars;
  document.getElementById('tCt').value = t.content;
  document.getElementById('tSo').value = t.sort_order;
  document.getElementById('tAc').checked = t.is_active == 1;
  openModal('mTm');
}

/* ── Credential Log — password reveal ───── */
function togglePw(btn) {
  const row  = btn.closest('div');
  const mask  = row.querySelector('.pw-mask');
  const plain = row.querySelector('.pw-plain');
  const show  = plain.style.display === 'none';
  mask.style.display  = show ? 'none'   : '';
  plain.style.display = show ? 'inline' : 'none';
  btn.textContent = show ? '🙈' : '👁';
}
function toggleAllPw(btn) {
  const show = btn.textContent === 'បង្ហាញ';
  btn.textContent = show ? 'លាក់' : 'បង្ហាញ';
  document.querySelectorAll('.pw-mask').forEach(el  => el.style.display  = show ? 'none'   : '');
  document.querySelectorAll('.pw-plain').forEach(el => el.style.display  = show ? 'inline' : 'none');
  document.querySelectorAll('.pw-btn').forEach(el   => el.textContent    = show ? '🙈'     : '👁');
}

/* ── Dashboard Category Modal ────────────── */
function openDashCatModal(cat) {
  if (!cat || cat === 0) {
    document.getElementById('mDashCatTitle').textContent = '⊞ បន្ថែម Tile ថ្មី';
    document.getElementById('dcId').value     = '0';
    document.getElementById('dcIcon').value   = '📌';
    document.getElementById('dcLabel').value  = '';
    document.getElementById('dcSort').value   = '0';
    document.getElementById('dcActive').checked = true;
    pickDashColor('mi-blue','#dbeafe');
    document.getElementById('dcPreviewIcon').textContent  = '📌';
    document.getElementById('dcPreviewLabel').textContent = 'Tile';
  } else {
    document.getElementById('mDashCatTitle').textContent = '✏️ កែ — ' + cat.label;
    document.getElementById('dcId').value     = cat.id;
    document.getElementById('dcIcon').value   = cat.icon;
    document.getElementById('dcLabel').value  = cat.label;
    document.getElementById('dcSort').value   = cat.sort_order;
    document.getElementById('dcActive').checked = cat.is_active == 1;
    const colorMap = {
      'mi-blue':'#dbeafe','mi-purple':'#ede9fe','mi-orange':'#ffedd5',
      'mi-pink':'#fce7f3','mi-green':'#dcfce7','mi-teal':'#ccfbf1',
      'mi-red':'#fee2e2','mi-yellow':'#fef9c3','mi-indigo':'#e0e7ff',
      'mi-cyan':'#cffafe','mi-lime':'#ecfccb','mi-rose':'#ffe4e6',
      'mi-sky':'#e0f2fe','mi-violet':'#f5f3ff','mi-amber':'#fef3c7',
      'mi-slate':'#f1f5f9','mi-emerald':'#d1fae5','mi-fuchsia':'#fdf4ff'
    };
    pickDashColor(cat.color, colorMap[cat.color] || '#dbeafe');
    document.getElementById('dcPreviewIcon').textContent  = cat.icon;
    document.getElementById('dcPreviewLabel').textContent = cat.label;
  }
  openModal('mDashCat');
}
function pickDashColor(cls, bg) {
  document.getElementById('dcColor').value = cls;
  document.getElementById('dcPreview').style.background = bg;
  document.querySelectorAll('#colorPicker .color-swatch').forEach(sw => {
    sw.style.borderColor = sw.dataset.color === cls ? '#0054a6' : 'transparent';
    sw.style.transform   = sw.dataset.color === cls ? 'scale(1.15)' : 'scale(1)';
  });
}

/* ── Role Category Modal ─────────────────── */
function resetRoleModal(){
  document.getElementById('mRoleTitle').textContent = '🏷️ បន្ថែមប្រភេទអ្នកប្រើ';
  document.getElementById('rId').value    = '0';
  document.getElementById('rSlug').value  = '';
  document.getElementById('rSlug').removeAttribute('readonly');
  document.getElementById('rLabel').value = '';
  document.getElementById('rIcon').value  = '👤';
  document.getElementById('rColor').value = 'b-blue';
  document.getElementById('rSort').value  = '0';
  openModal('mRole');
}
function editRole(r){
  document.getElementById('mRoleTitle').textContent = '✏️ កែប្រែ — ' + r.label;
  document.getElementById('rId').value    = r.id;
  document.getElementById('rSlug').value  = r.slug;
  document.getElementById('rSlug').setAttribute('readonly','readonly');
  document.getElementById('rLabel').value = r.label;
  document.getElementById('rIcon').value  = r.icon  || '👤';
  document.getElementById('rColor').value = r.color || 'b-blue';
  document.getElementById('rSort').value  = r.sort_order || '0';
  openModal('mRole');
}

/* ── Auto-fade flash message ────────────────── */
const flashEl = document.getElementById('flash');
if(flashEl && !flashEl.dataset.persist) setTimeout(() => { flashEl.style.transition='opacity .6s'; flashEl.style.opacity='0'; setTimeout(()=>flashEl.remove(),700); }, 3500);
</script>
</body>
</html>
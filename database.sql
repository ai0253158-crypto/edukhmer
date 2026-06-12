-- ============================================================
--  EduKhmer Database Schema
--  Created for EduKhmer Digital Teacher Assistant
-- ============================================================

CREATE DATABASE IF NOT EXISTS edukhmer
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE edukhmer;

-- ── ADMIN ACCOUNTS ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admins (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  username    VARCHAR(80)  NOT NULL UNIQUE,
  email       VARCHAR(160) NOT NULL UNIQUE,
  password    VARCHAR(255) NOT NULL,          -- bcrypt hash
  full_name   VARCHAR(160),
  role        ENUM('superadmin','admin','editor') NOT NULL DEFAULT 'admin',
  is_active   TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_login  DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Default superadmin  (password: Admin@1234)
-- Hash generated with: password_hash('Admin@1234', PASSWORD_BCRYPT)
INSERT INTO admins (username, email, password, full_name, role) VALUES
('admin', 'admin@edukhmer.com',
 '$2y$12$V7gK3bLqW5NjR0Xu2Yz8OuHMBPwQaT4sICdEfGhJKlNoP1RsUvWxY',
 'EduKhmer Admin', 'superadmin');

-- ── USERS (teachers / students who register on the site) ────
CREATE TABLE IF NOT EXISTS users (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  first_name  VARCHAR(80)  NOT NULL,
  last_name   VARCHAR(80)  NOT NULL,
  email       VARCHAR(160) NOT NULL UNIQUE,
  phone       VARCHAR(30),
  password    VARCHAR(255) NOT NULL,
  role        ENUM('teacher','student','parent') NOT NULL DEFAULT 'teacher',
  is_active   TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── SCHOOLS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schools (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  province    VARCHAR(100),
  address     TEXT,
  phone       VARCHAR(30),
  email       VARCHAR(160),
  is_active   TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── CLASSES ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS classes (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  school_id   INT,
  teacher_id  INT,
  name        VARCHAR(100) NOT NULL,
  grade       VARCHAR(20),
  academic_year VARCHAR(20),
  is_active   TINYINT(1) NOT NULL DEFAULT 1,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (school_id)  REFERENCES schools(id) ON DELETE SET NULL,
  FOREIGN KEY (teacher_id) REFERENCES users(id)   ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── STUDENTS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS students (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  class_id      INT,
  student_code  VARCHAR(30) UNIQUE,
  first_name    VARCHAR(80) NOT NULL,
  last_name     VARCHAR(80) NOT NULL,
  gender        ENUM('male','female','other'),
  dob           DATE,
  parent_phone  VARCHAR(30),
  address       TEXT,
  photo_url     VARCHAR(300),
  is_active     TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── SUBJECTS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subjects (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  code        VARCHAR(20),
  description TEXT,
  is_active   TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── SCORES ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scores (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  student_id  INT NOT NULL,
  subject_id  INT NOT NULL,
  class_id    INT,
  score_type  ENUM('midterm','final','assignment','quiz','attendance') DEFAULT 'final',
  score       DECIMAL(5,2),
  max_score   DECIMAL(5,2) DEFAULT 100,
  note        TEXT,
  scored_at   DATE,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
  FOREIGN KEY (class_id)   REFERENCES classes(id)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── ATTENDANCE ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attendance (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  student_id  INT NOT NULL,
  class_id    INT,
  attend_date DATE NOT NULL,
  status      ENUM('present','absent','late','excused') DEFAULT 'present',
  note        TEXT,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (class_id)   REFERENCES classes(id)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── SITE CONTENT (editable sections) ────────────────────────
CREATE TABLE IF NOT EXISTS site_content (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  section_key VARCHAR(80) NOT NULL UNIQUE,   -- e.g. 'hero_title', 'hero_subtitle'
  content     TEXT,
  updated_by  INT,
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Default editable content matching the HTML
INSERT INTO site_content (section_key, content) VALUES
('hero_title',           'ជំនួយការគ្រូបង្រៀនឆ្លាតវៃ និងទំនើប'),
('hero_subtitle',        'គ្រប់គ្រងសិស្ស ពិន្ទុ និងវត្តមាន ក្នុងពេលតែមួយ។'),
('hero_badge_text',      'ប្រព័ន្ធបង្រៀនឌីជីថល ថ្មីបំផុត ២០២៥'),
('stat_teachers',        '5,000+'),
('stat_schools',         '120+'),
('stat_satisfaction',    '98%'),
('footer_description',   'ប្រព័ន្ធគ្រប់គ្រងការបង្រៀនឌីជីថល សម្រាប់គ្រូបង្រៀននៅកម្ពុជា'),
('plan_free_price',      'Free'),
('plan_pro_price',       '$9'),
('plan_school_price',    '$49'),
('announcement',         'ប្រព័ន្ធ EduKhmer ២.០ ត្រៀមបើកដំណើរការ!');

-- ── PRICING PLANS ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plans (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  plan_key    VARCHAR(40) NOT NULL UNIQUE,
  name        VARCHAR(80),
  price       VARCHAR(20),
  period      VARCHAR(30),
  is_featured TINYINT(1) DEFAULT 0,
  features    TEXT,                           -- JSON array of feature strings
  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO plans (plan_key, name, price, period, is_featured, features) VALUES
('free',   'ឥតគិតថ្លៃ', 'Free',  '',           0,
 '["គ្រប់គ្រងសិស្សរហូតដល់ 30 នាក់","ប្រព័ន្ធពិន្ទុមូលដ្ឋាន","វត្តមានឌីជីថល","របាយការណ៍ PDF"]'),
('pro',    'Pro',        '$9',    '/ ខែ',        1,
 '["គ្រប់គ្រងសិស្សគ្មានដែនកំណត់","AI វិភាគស្វ័យប្រវត្តិ","ការជូនដំណឹង SMS","ការនាំចូល/ចេញ Excel","ការគាំទ្រអាទិភាព"]'),
('school', 'សាលា',       '$49',   '/ ខែ / សាលា', 0,
 '["រួមបញ្ចូលគ្រូបង្រៀនគ្មានដែនកំណត់","ផ្ទាំងគ្រប់គ្រងសាលា","ការភ្ជាប់ API","ការបណ្តុះបណ្តាលផ្ទាល់","SLA 99.9%"]');

-- ── TESTIMONIALS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS testimonials (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  author_name VARCHAR(120) NOT NULL,
  author_role VARCHAR(160),
  avatar_color VARCHAR(20) DEFAULT '#0054a6',
  stars       TINYINT DEFAULT 5,
  content     TEXT NOT NULL,
  is_active   TINYINT(1) DEFAULT 1,
  sort_order  INT DEFAULT 0,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO testimonials (author_name, author_role, avatar_color, stars, content, sort_order) VALUES
('អ្នកគ្រូ សុខ វណ្ណា',   'គ្រូបង្រៀន · សាលាបឋមសិក្សាភ្នំពេញ', '#0054a6', 5, 'EduKhmer ជួយខ្ញុំសន្សំពេលវេលាបានច្រើន ខ្ញុំអាចគ្រប់គ្រងពិន្ទុ និងវត្តមានសិស្សសម្រាប់ 3 ថ្នាក់ ក្នុងពេលតែ 10 នាទី!', 1),
('លោកគ្រូ ហ៊ុន ចន្ទ្រា', 'គ្រូណែនាំ · វិទ្យាល័យព្រះស៊ីសុវត្ថិ',  '#1b8a4c', 5, 'ប្រព័ន្ធ AI វិភាគដំណើរការសិស្ស ជួយខ្ញុំកំណត់ ឬស្ងគ្ររ​ ជួយសិស្សបានត្រឹមត្រូវ។ ល្អឥតខ្ចោះ!', 2),
('អ្នកគ្រូ លី ស្រីម៉ែ',  'ប្រធានសាលា · AIS International School',  '#e53935', 5, 'ការគ្រប់គ្រងគ្រូ និងសិស្សសម្រាប់ 500+ នាក់ ងាយស្រួលជាងពីមុនណាស់ ។ ខ្ញុំណែនាំ EduKhmer ដល់គ្រូទាំងអស់!', 3);

-- ── ADMIN SESSION LOG ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_sessions (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  admin_id    INT NOT NULL,
  ip_address  VARCHAR(45),
  user_agent  VARCHAR(300),
  logged_in   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  logged_out  DATETIME,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
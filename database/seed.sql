-- ==========================================
-- PAMGuard INITIAL USERS
-- ==========================================

INSERT OR IGNORE INTO users
(username, email, status)
VALUES
('admin', 'admin@pamguard.local', 'ACTIVE'),
('analyst', 'analyst@pamguard.local', 'ACTIVE'),
('auditor', 'auditor@pamguard.local', 'ACTIVE');


-- ==========================================
-- ROLES
-- ==========================================

INSERT OR IGNORE INTO roles
(name, description)
VALUES
(
    'PAM_ADMIN',
    'Manage privileged accounts, policies and access approvals'
),
(
    'SECURITY_ANALYST',
    'Request privileged access and investigate security events'
),
(
    'AUDITOR',
    'Review audit records and generate compliance evidence'
);


-- ==========================================
-- USER ROLE ASSIGNMENTS
-- ==========================================

INSERT OR IGNORE INTO user_roles (user_id, role_id)
SELECT
    u.id,
    r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'admin'
AND r.name = 'PAM_ADMIN';


INSERT OR IGNORE INTO user_roles (user_id, role_id)
SELECT
    u.id,
    r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'analyst'
AND r.name = 'SECURITY_ANALYST';


INSERT OR IGNORE INTO user_roles (user_id, role_id)
SELECT
    u.id,
    r.id
FROM users u
CROSS JOIN roles r
WHERE u.username = 'auditor'
AND r.name = 'AUDITOR';


-- ==========================================
-- SAFES
-- ==========================================

INSERT OR IGNORE INTO safes
(name, description)
VALUES
(
    'Linux-Production',
    'Production Linux privileged accounts'
),
(
    'Windows-Servers',
    'Windows server privileged accounts'
),
(
    'Database-Servers',
    'Production database privileged accounts'
);


-- ==========================================
-- PLATFORMS
-- ==========================================

INSERT OR IGNORE INTO platforms
(name, description)
VALUES
(
    'Linux',
    'Linux and Unix-based systems'
),
(
    'Windows',
    'Microsoft Windows servers'
),
(
    'Database',
    'Production database systems'
);
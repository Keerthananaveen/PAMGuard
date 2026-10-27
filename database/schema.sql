PRAGMA foreign_keys = ON;

-- ==========================================
-- USERS
-- ==========================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ==========================================
-- ROLES
-- ==========================================

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);


-- ==========================================
-- USER ↔ ROLE MAPPING
-- ==========================================

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,

    PRIMARY KEY (user_id, role_id),

    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY (role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE
);


-- ==========================================
-- SAFES
-- ==========================================

CREATE TABLE IF NOT EXISTS safes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ==========================================
-- PLATFORMS
-- ==========================================

CREATE TABLE IF NOT EXISTS platforms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);


-- ==========================================
-- PRIVILEGED ACCOUNTS
-- ==========================================

CREATE TABLE IF NOT EXISTS privileged_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL,
    hostname TEXT NOT NULL,

    platform_id INTEGER NOT NULL,
    safe_id INTEGER NOT NULL,

    credential_hash TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'DISABLED')),

    last_rotation TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(username, hostname),

    FOREIGN KEY (platform_id)
        REFERENCES platforms(id),

    FOREIGN KEY (safe_id)
        REFERENCES safes(id)
);


-- ==========================================
-- ACCESS POLICIES
-- ==========================================

CREATE TABLE IF NOT EXISTS access_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT NOT NULL UNIQUE,

    safe_id INTEGER NOT NULL,

    max_duration_minutes INTEGER NOT NULL
        CHECK (max_duration_minutes > 0),

    approval_required INTEGER NOT NULL DEFAULT 1
        CHECK (approval_required IN (0, 1)),

    rotation_interval_hours INTEGER NOT NULL
        CHECK (rotation_interval_hours > 0),

    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1)),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (safe_id)
        REFERENCES safes(id)
);


-- ==========================================
-- ACCESS REQUESTS
-- ==========================================

CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    request_id TEXT NOT NULL UNIQUE,

    user_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,

    reason TEXT NOT NULL,

    requested_duration_minutes INTEGER NOT NULL
        CHECK (requested_duration_minutes > 0),

    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'APPROVED',
                'CHECKED_OUT',
                'REJECTED',
                'EXPIRED'
            )
        ),

    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TEXT,
    approved_by INTEGER,

    FOREIGN KEY (user_id)
        REFERENCES users(id),

    FOREIGN KEY (account_id)
        REFERENCES privileged_accounts(id),

    FOREIGN KEY (approved_by)
        REFERENCES users(id)
);


-- ==========================================
-- SESSIONS
-- ==========================================

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    session_id TEXT NOT NULL UNIQUE,

    user_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,

    start_time TEXT NOT NULL,
    end_time TEXT,

    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (
            status IN (
                'ACTIVE',
                'CLOSED',
                'EXPIRED'
            )
        ),

    source_ip TEXT,
    reason TEXT NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(id),

    FOREIGN KEY (account_id)
        REFERENCES privileged_accounts(id)
);


-- ==========================================
-- AUDIT LOGS
-- ==========================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    event_type TEXT NOT NULL,

    user_id INTEGER,

    account_id INTEGER,

    session_id TEXT,

    result TEXT NOT NULL,

    details TEXT,

    source_ip TEXT,

    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users(id),

    FOREIGN KEY (account_id)
        REFERENCES privileged_accounts(id)
);


-- ==========================================
-- PASSWORD ROTATIONS
-- ==========================================

CREATE TABLE IF NOT EXISTS password_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    account_id INTEGER NOT NULL,

    rotation_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    result TEXT NOT NULL
        CHECK (result IN ('SUCCESS', 'FAILED')),

    performed_by INTEGER,

    FOREIGN KEY (account_id)
        REFERENCES privileged_accounts(id),

    FOREIGN KEY (performed_by)
        REFERENCES users(id)
);
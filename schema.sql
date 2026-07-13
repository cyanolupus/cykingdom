CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    points INTEGER NOT NULL DEFAULT 0,
    last_gacha_date TEXT,
    icon_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_points ON users(points DESC);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    aaguid BLOB NOT NULL,
    is_backed_up INTEGER DEFAULT 0,
    is_user_verified INTEGER DEFAULT 0,
    attestation_fmt TEXT
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    pending_user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gifts (
    id TEXT PRIMARY KEY,
    points INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_gifts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    gift_id TEXT NOT NULL REFERENCES gifts(id),
    is_opened INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS matches (
    id TEXT PRIMARY KEY,
    player1_id TEXT NOT NULL REFERENCES users(id),
    player1_hand TEXT NOT NULL,
    player2_id TEXT REFERENCES users(id),
    player2_hand TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

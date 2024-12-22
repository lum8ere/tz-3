CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);

CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
    user_id TEXT NOT NULL,
    hashed_token TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
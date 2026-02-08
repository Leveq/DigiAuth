-- 001_initial_schema.up.sql
-- DigiAuth initial database schema

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Users ──────────────────────────────────────────────────────────
-- The DGB address is the identity anchor. No passwords are ever stored.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dgb_address     VARCHAR(62) NOT NULL UNIQUE,
    display_name    VARCHAR(100) DEFAULT '',
    avatar_url      TEXT DEFAULT '',
    bio             TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_users_dgb_address ON users(dgb_address);
CREATE INDEX idx_users_created_at ON users(created_at);

-- ─── Sessions ───────────────────────────────────────────────────────
-- Each session maps to a refresh token. Access tokens are stateless JWTs.
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  VARCHAR(64) NOT NULL,
    ip_address          INET,
    user_agent          TEXT DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- ─── OAuth Clients (Phase 4, created now for forward compatibility) ─
CREATE TABLE oauth_clients (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id           VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash  VARCHAR(128) NOT NULL,
    name                VARCHAR(100) NOT NULL,
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_owner_id ON oauth_clients(owner_id);

-- ─── Posts (Demo app, Phase 3) ──────────────────────────────────────
CREATE TABLE posts (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content     TEXT NOT NULL CHECK (char_length(content) <= 1000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_posts_user_id ON posts(user_id);
CREATE INDEX idx_posts_created_at ON posts(created_at DESC);

-- ─── Trigger: auto-update updated_at ────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trigger_posts_updated_at
    BEFORE UPDATE ON posts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

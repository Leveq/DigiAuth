-- 001_initial_schema.down.sql
-- Rollback: Drop all tables created in the initial migration

DROP TRIGGER IF EXISTS trigger_posts_updated_at ON posts;
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at();

DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "uuid-ossp";

-- Run this in psql or a migration tool
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  username_norm TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE TABLE IF NOT EXISTS scores (
  id SERIAL PRIMARY KEY,
  user_id INTEGER,
  name TEXT NOT NULL,
  score INTEGER NOT NULL,
  difficulty TEXT NOT NULL CHECK (difficulty IN ('easy', 'normal', 'hard')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  duration_ms INTEGER,
  did_win BOOLEAN,
  score INTEGER,
  difficulty TEXT CHECK (difficulty IN ('easy', 'normal', 'hard'))
);

CREATE TABLE IF NOT EXISTS request_rate_limits (
  limiter_key TEXT NOT NULL,
  bucket_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (limiter_key, bucket_start)
);

ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS user_id INTEGER;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'scores_user_id_fkey'
      AND conrelid = 'scores'::regclass
  ) THEN
    ALTER TABLE scores
      ADD CONSTRAINT scores_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
END
$$;
ALTER TABLE user_sessions
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days');
ALTER TABLE user_sessions
  ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '7 days');

DROP INDEX IF EXISTS scores_name_difficulty_idx;
CREATE UNIQUE INDEX IF NOT EXISTS scores_user_difficulty_idx ON scores (user_id, difficulty);
CREATE INDEX IF NOT EXISTS scores_difficulty_score_idx ON scores (difficulty, score DESC);
CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx ON user_sessions (expires_at);
CREATE INDEX IF NOT EXISTS game_sessions_user_id_idx ON game_sessions (user_id);
CREATE INDEX IF NOT EXISTS game_sessions_started_at_idx ON game_sessions (started_at);
CREATE INDEX IF NOT EXISTS request_rate_limits_bucket_start_idx ON request_rate_limits (bucket_start);

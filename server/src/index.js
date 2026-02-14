import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const { Pool } = pkg;
const DEFAULT_CORS_ORIGINS = 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000,http://127.0.0.1:3000,https://shadowdog-client.onrender.com';
const PASSWORD_MIN_LENGTH = 6;
const PASSWORD_MAX_LENGTH = 128;
const DEFAULT_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const DEFAULT_API_BODY_LIMIT_BYTES = 16 * 1024;
const scryptAsync = promisify(crypto.scrypt);

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null) return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseTrustProxy(value, fallback) {
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['false', '0', 'off', 'no'].includes(normalized)) return false;
  if (['true', 'on', 'yes'].includes(normalized)) return true;
  const hopCount = Number.parseInt(normalized, 10);
  if (Number.isFinite(hopCount) && hopCount >= 0) return hopCount;
  return fallback;
}

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
}

function normalizeOrigin(origin) {
  return typeof origin === 'string' ? origin.trim().replace(/\/+$/, '') : '';
}

function normalizeIp(req) {
  const ip = req?.ip || req?.socket?.remoteAddress || 'unknown';
  return typeof ip === 'string' ? ip.trim() : 'unknown';
}

function parseCookies(cookieHeader) {
  if (!cookieHeader || typeof cookieHeader !== 'string') return {};
  return cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const eq = part.indexOf('=');
      if (eq <= 0) return acc;
      const key = part.slice(0, eq).trim();
      const value = part.slice(eq + 1).trim();
      if (!key) return acc;
      try {
        acc[key] = decodeURIComponent(value);
      } catch {
        acc[key] = value;
      }
      return acc;
    }, {});
}

function serializeSessionCookie(name, value, maxAgeSeconds, secure) {
  const encodedName = encodeURIComponent(name);
  const encodedValue = encodeURIComponent(value);
  const parts = [
    `${encodedName}=${encodedValue}`,
    'Path=/',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function validateSignupPayload(body) {
  const { username, password } = body || {};
  const trimmedUsername = typeof username === 'string' ? username.trim() : '';
  if (!trimmedUsername) {
    return { error: 'Username is required' };
  }
  if (trimmedUsername.length < 3) {
    return { error: 'Username must be at least 3 characters' };
  }
  if (trimmedUsername.length > 16) {
    return { error: 'Username must be at most 16 characters' };
  }
  if (!/^[A-Za-z0-9_]+$/.test(trimmedUsername)) {
    return { error: 'Username can contain only letters, numbers, and underscore' };
  }
  if (typeof password !== 'string' || password.length === 0) {
    return { error: 'Password is required' };
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return { error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` };
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return { error: `Password must be at most ${PASSWORD_MAX_LENGTH} characters` };
  }
  return { trimmedUsername, usernameNorm: normalizeUsername(trimmedUsername) };
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = (await scryptAsync(password, salt, 64)).toString('hex');
  return `${salt}:${hash}`;
}

async function verifyPassword(password, storedHash) {
  const [salt, hashHex] = (storedHash || '').split(':');
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scryptAsync(password, salt, 64);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function ensureSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      username_norm TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scores (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      name TEXT NOT NULL,
      score INTEGER NOT NULL,
      difficulty TEXT NOT NULL CHECK (difficulty IN ('easy', 'normal', 'hard')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS game_sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMPTZ,
      duration_ms INTEGER,
      did_win BOOLEAN,
      score INTEGER,
      difficulty TEXT CHECK (difficulty IN ('easy', 'normal', 'hard'))
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS request_rate_limits (
      limiter_key TEXT NOT NULL,
      bucket_start TIMESTAMPTZ NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (limiter_key, bucket_start)
    )
  `);
  await pool.query('ALTER TABLE scores ADD COLUMN IF NOT EXISTS user_id INTEGER');
  await pool.query(`
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
  `);
  await pool.query(`
    ALTER TABLE user_sessions
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
  `);
  await pool.query('DROP INDEX IF EXISTS scores_name_difficulty_idx');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS scores_user_difficulty_idx ON scores (user_id, difficulty)');
  await pool.query('CREATE INDEX IF NOT EXISTS scores_difficulty_score_idx ON scores (difficulty, score DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx ON user_sessions (user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx ON user_sessions (expires_at)');
  await pool.query('CREATE INDEX IF NOT EXISTS game_sessions_user_id_idx ON game_sessions (user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS game_sessions_started_at_idx ON game_sessions (started_at)');
}

async function hasRequiredSchema(pool, { requireRateLimitTable = false } = {}) {
  const sql = `
    SELECT
      to_regclass('public.users') IS NOT NULL AS users_exists,
      to_regclass('public.user_sessions') IS NOT NULL AS user_sessions_exists,
      to_regclass('public.scores') IS NOT NULL AS scores_exists,
      to_regclass('public.game_sessions') IS NOT NULL AS game_sessions_exists,
      to_regclass('public.request_rate_limits') IS NOT NULL AS request_rate_limits_exists
  `;
  const result = await pool.query(sql);
  const row = result.rows[0] || {};
  const baseOk = Boolean(row.users_exists && row.user_sessions_exists && row.scores_exists && row.game_sessions_exists);
  if (!requireRateLimitTable) return baseOk;
  return baseOk && Boolean(row.request_rate_limits_exists);
}

function timingSafeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a, 'utf8');
  const bBuf = Buffer.from(b, 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function createInMemoryRateLimiter({
  max,
  windowMs,
  keyFn,
  maxEntries = 10000,
  errorBody = { error: 'Too many requests' },
}) {
  const state = new Map();
  let lastCleanupAt = Date.now();

  function cleanup(now) {
    if (now - lastCleanupAt < windowMs) return;
    lastCleanupAt = now;
    for (const [key, value] of state.entries()) {
      if (now - value.windowStart >= windowMs) state.delete(key);
    }
  }

  function evictIfNeeded(now) {
    if (state.size < maxEntries) return;
    cleanup(now);
    if (state.size < maxEntries) return;
    const removeCount = Math.max(1, Math.floor(maxEntries * 0.1));
    let removed = 0;
    for (const key of state.keys()) {
      state.delete(key);
      removed += 1;
      if (removed >= removeCount) break;
    }
  }

  return (req, res, next) => {
    const now = Date.now();
    cleanup(now);
    let key = 'unknown';
    try {
      key = keyFn(req) || 'unknown';
    } catch {
      key = 'unknown';
    }
    const current = state.get(key);
    if (!current || now - current.windowStart >= windowMs) {
      evictIfNeeded(now);
      state.set(key, { count: 1, windowStart: now });
      return next();
    }
    if (current.count >= max) {
      return res.status(429).json(errorBody);
    }
    current.count += 1;
    return next();
  };
}

function createPostgresRateLimiter({
  pool,
  name = 'default',
  max,
  windowMs,
  keyFn,
  errorBody = { error: 'Too many requests' },
}) {
  let lastCleanupAt = 0;
  const cleanupEveryMs = Math.max(windowMs, 60 * 1000);

  return async (req, res, next) => {
    const now = Date.now();
    let key = 'unknown';
    try {
      key = keyFn(req) || 'unknown';
    } catch {
      key = 'unknown';
    }
    const namespacedKey = `${name}:${String(key)}`;
    const safeKey = crypto.createHash('sha256').update(namespacedKey).digest('hex');
    const bucketStartMs = Math.floor(now / windowMs) * windowMs;
    const bucketStartIso = new Date(bucketStartMs).toISOString();

    try {
      if (now - lastCleanupAt >= cleanupEveryMs) {
        lastCleanupAt = now;
        await pool.query(
          'DELETE FROM request_rate_limits WHERE bucket_start < NOW() - ($1::bigint * interval \'1 millisecond\')',
          [windowMs * 2],
        );
      }
      const sql = `
        INSERT INTO request_rate_limits (limiter_key, bucket_start, count, updated_at)
        VALUES ($1, $2::timestamptz, 1, NOW())
        ON CONFLICT (limiter_key, bucket_start)
        DO UPDATE SET
          count = request_rate_limits.count + 1,
          updated_at = NOW()
        RETURNING count
      `;
      const result = await pool.query(sql, [safeKey, bucketStartIso]);
      const count = Number(result.rows?.[0]?.count || 0);
      if (count > max) {
        return res.status(429).json(errorBody);
      }
      return next();
    } catch {
      return res.status(503).json({ error: 'Rate limiter unavailable' });
    }
  };
}

export function createApp({
  pool,
  adminResetToken = process.env.ADMIN_RESET_TOKEN,
  adminUsername = process.env.ADMIN_USERNAME || 'harel',
  sessionCookieName = process.env.SESSION_COOKIE_NAME || 'shadowdog_session',
  rateLimitStore = String(process.env.RATE_LIMIT_STORE || 'memory').trim().toLowerCase(),
  corsOrigins = process.env.CORS_ORIGINS || '',
  scoreRateLimitMax = parsePositiveInt(process.env.SCORE_RATE_LIMIT_MAX, 30),
  scoreRateLimitWindowMs = parsePositiveInt(process.env.SCORE_RATE_LIMIT_WINDOW_MS, 60000),
  adminRateLimitMax = parsePositiveInt(process.env.ADMIN_RATE_LIMIT_MAX, 5),
  adminRateLimitWindowMs = parsePositiveInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS, 60000),
  authRateLimitMax = parsePositiveInt(process.env.AUTH_RATE_LIMIT_MAX, 10),
  authRateLimitWindowMs = parsePositiveInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 60000),
  authIdentityRateLimitMax = parsePositiveInt(process.env.AUTH_IDENTITY_RATE_LIMIT_MAX, 5),
  authIdentityRateLimitWindowMs = parsePositiveInt(process.env.AUTH_IDENTITY_RATE_LIMIT_WINDOW_MS, 60000),
  analyticsRateLimitMax = parsePositiveInt(process.env.ANALYTICS_RATE_LIMIT_MAX, 120),
  analyticsRateLimitWindowMs = parsePositiveInt(process.env.ANALYTICS_RATE_LIMIT_WINDOW_MS, 60000),
  rateLimiterMaxEntries = parsePositiveInt(process.env.RATE_LIMITER_MAX_ENTRIES, 10000),
  apiBodyLimitBytes = parsePositiveInt(process.env.API_BODY_LIMIT_BYTES, DEFAULT_API_BODY_LIMIT_BYTES),
  sessionTtlMs = parsePositiveInt(process.env.SESSION_TTL_MS, DEFAULT_SESSION_TTL_MS),
  trustProxy = parseTrustProxy(process.env.TRUST_PROXY, process.env.NODE_ENV === 'production' ? 1 : false),
} = {}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new Error('A database pool with a query method is required');
  }

  const allowedOrigins = `${DEFAULT_CORS_ORIGINS},${corsOrigins}`
    .split(',')
    .map(normalizeOrigin)
    .filter(Boolean);
  const allowedOriginsSet = new Set(allowedOrigins);
  const allowAnyOrigin = allowedOriginsSet.has('*');

  const app = express();
  app.set('trust proxy', trustProxy);
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    res.setHeader('Cache-Control', 'no-store');
    if (req.secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });
  app.use(cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      const normalized = normalizeOrigin(origin);
      if (allowAnyOrigin || allowedOriginsSet.has(normalized)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  }));
  app.use(express.json({ limit: apiBodyLimitBytes }));

  const createRateLimiter = (config) => {
    if (rateLimitStore === 'database') {
      return createPostgresRateLimiter({ pool, ...config });
    }
    return createInMemoryRateLimiter({ ...config, maxEntries: rateLimiterMaxEntries });
  };

  const scoreRateLimitMiddleware = createRateLimiter({
    name: 'scores_write',
    max: scoreRateLimitMax,
    windowMs: scoreRateLimitWindowMs,
    keyFn: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  });
  const authRateLimitMiddleware = createRateLimiter({
    name: 'auth_ip',
    max: authRateLimitMax,
    windowMs: authRateLimitWindowMs,
    keyFn: (req) => normalizeIp(req),
  });
  const authIdentityRateLimitMiddleware = createRateLimiter({
    name: 'auth_identity',
    max: authIdentityRateLimitMax,
    windowMs: authIdentityRateLimitWindowMs,
    keyFn: (req) => `${normalizeIp(req)}:${normalizeUsername(req.body?.username) || 'unknown'}`,
  });
  const analyticsRateLimitMiddleware = createRateLimiter({
    name: 'analytics',
    max: analyticsRateLimitMax,
    windowMs: analyticsRateLimitWindowMs,
    keyFn: (req) => `${normalizeIp(req)}:${req.user?.id || 'anon'}`,
  });
  const adminRateLimitMiddleware = createRateLimiter({
    name: 'admin',
    max: adminRateLimitMax,
    windowMs: adminRateLimitWindowMs,
    keyFn: (req) => normalizeIp(req),
  });
  let lastExpiredSessionCleanupAt = 0;
  const sessionCleanupIntervalMs = Math.min(sessionTtlMs, 60 * 60 * 1000);

  async function cleanupExpiredSessions(now = Date.now()) {
    if (now - lastExpiredSessionCleanupAt < sessionCleanupIntervalMs) return;
    lastExpiredSessionCleanupAt = now;
    await pool.query('DELETE FROM user_sessions WHERE expires_at <= NOW()');
  }

  async function issueSession(userId) {
    const token = createSessionToken();
    const expiresAt = new Date(Date.now() + sessionTtlMs).toISOString();
    await pool.query('INSERT INTO user_sessions (token, user_id, expires_at) VALUES ($1, $2, $3)', [token, userId, expiresAt]);
    return token;
  }

  function getRequestToken(req) {
    const authHeader = req.get('authorization') || '';
    const cookies = parseCookies(req.get('cookie') || '');
    const cookieToken = cookies[sessionCookieName] || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    return bearerToken || cookieToken;
  }

  async function requireAuth(req, res, next) {
    const token = getRequestToken(req);
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
      await cleanupExpiredSessions();
      const sql = `
        SELECT u.id, u.username, u.username_norm, us.token
        FROM user_sessions us
        JOIN users u ON u.id = us.user_id
        WHERE us.token = $1
          AND us.expires_at > NOW()
      `;
      const result = await pool.query(sql, [token]);
      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      req.user = result.rows[0];
      req.token = token;
      return next();
    } catch {
      return res.status(500).json({ error: 'Auth failed' });
    }
  }

  async function requireAdmin(req, res, next) {
    const normalizedAdminUsername = normalizeUsername(adminUsername);
    if (!normalizedAdminUsername) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return requireAuth(req, res, () => {
      if (req.user?.username_norm !== normalizedAdminUsername) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      return next();
    });
  }

  function requireAdminToken(req, res, next) {
    const providedToken = req.get('x-admin-token');
    if (!adminResetToken || !timingSafeEqualString(providedToken || '', adminResetToken)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  }

  app.get('/health', async (_req, res) => {
    try {
      await pool.query('SELECT 1 AS ok');
      return res.json({ ok: true, db: true });
    } catch {
      return res.status(500).json({ ok: false, db: false });
    }
  });

  app.post('/auth/signup', authRateLimitMiddleware, authIdentityRateLimitMiddleware, async (req, res) => {
    try {
      await cleanupExpiredSessions();
      const validation = validateSignupPayload(req.body);
      if (validation.error) {
        return res.status(400).json({ error: validation.error });
      }
      const { trimmedUsername, usernameNorm } = validation;
      const { password } = req.body;

      const passwordHash = await hashPassword(password);
      const userSql = `
        INSERT INTO users (username, username_norm, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, username
      `;
      const userResult = await pool.query(userSql, [trimmedUsername, usernameNorm, passwordHash]);
      const user = userResult.rows[0];
      const token = await issueSession(user.id);
      const cookie = serializeSessionCookie(sessionCookieName, token, sessionTtlMs / 1000, req.secure);
      res.setHeader('Set-Cookie', cookie);
      return res.status(201).json({ user });
    } catch (err) {
      if (err?.code === '23505') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Failed to signup' });
    }
  });

  app.post('/auth/login', authRateLimitMiddleware, authIdentityRateLimitMiddleware, async (req, res) => {
    try {
      await cleanupExpiredSessions();
      const { username, password } = req.body || {};
      const usernameNorm = normalizeUsername(username);
      if (
        !usernameNorm ||
        typeof password !== 'string' ||
        password.length < PASSWORD_MIN_LENGTH ||
        password.length > PASSWORD_MAX_LENGTH
      ) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      const userSql = 'SELECT id, username, password_hash FROM users WHERE username_norm = $1';
      const userResult = await pool.query(userSql, [usernameNorm]);
      if (userResult.rows.length === 0 || !(await verifyPassword(password, userResult.rows[0].password_hash))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const user = { id: userResult.rows[0].id, username: userResult.rows[0].username };
      const token = await issueSession(user.id);
      const cookie = serializeSessionCookie(sessionCookieName, token, sessionTtlMs / 1000, req.secure);
      res.setHeader('Set-Cookie', cookie);
      return res.json({ user });
    } catch {
      return res.status(500).json({ error: 'Failed to login' });
    }
  });

  app.get('/auth/me', requireAuth, async (req, res) => {
    return res.json({
      user: {
        id: req.user.id,
        username: req.user.username,
      },
    });
  });

  app.post('/auth/logout', async (req, res) => {
    try {
      const token = getRequestToken(req);
      if (token) {
        await pool.query('DELETE FROM user_sessions WHERE token = $1', [token]);
      }
      const cookie = serializeSessionCookie(sessionCookieName, '', 0, req.secure);
      res.setHeader('Set-Cookie', cookie);
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ error: 'Failed to logout' });
    }
  });

  app.get('/scores', async (req, res) => {
    try {
      const difficulty = req.query.difficulty;
      const parsedLimit = Number.parseInt(req.query.limit || '10', 10);
      const limit = Number.isNaN(parsedLimit) ? 10 : parsedLimit;
      const safeLimit = Math.min(Math.max(limit, 1), 50);
      const params = [];
      let where = '';
      if (difficulty) {
        params.push(difficulty);
        where = `WHERE difficulty = $${params.length}`;
      }
      params.push(safeLimit);
      const sql = `SELECT name, score, difficulty, created_at FROM scores ${where} ORDER BY score DESC, created_at ASC LIMIT $${params.length}`;
      const result = await pool.query(sql, params);
      res.json(result.rows);
    } catch {
      res.status(500).json({ error: 'Failed to fetch scores' });
    }
  });

  app.post('/scores', requireAuth, scoreRateLimitMiddleware, async (req, res) => {
    try {
      const { score, difficulty } = req.body || {};
      if (!Number.isInteger(score) || score < 0) return res.status(400).json({ error: 'Invalid score' });
      if (!['easy', 'normal', 'hard'].includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });

      const sql = `
      INSERT INTO scores (user_id, name, score, difficulty)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_id, difficulty)
      DO UPDATE SET score = EXCLUDED.score, name = EXCLUDED.name, created_at = NOW()
      WHERE EXCLUDED.score > scores.score
      RETURNING id, name, score, difficulty, created_at
    `;
      const params = [req.user.id, req.user.username, score, difficulty];
      const result = await pool.query(sql, params);
      if (result.rows.length === 0) {
        return res.status(200).json({ ok: true, updated: false });
      }
      return res.status(201).json(result.rows[0]);
    } catch {
      return res.status(500).json({ error: 'Failed to save score' });
    }
  });

  app.post('/analytics/session/start', requireAuth, analyticsRateLimitMiddleware, async (req, res) => {
    try {
      const sql = `
        INSERT INTO game_sessions (user_id, started_at)
        VALUES ($1, NOW())
        RETURNING id, started_at
      `;
      const result = await pool.query(sql, [req.user.id]);
      return res.status(201).json(result.rows[0]);
    } catch {
      return res.status(500).json({ error: 'Failed to start session' });
    }
  });

  app.post('/analytics/session/end', requireAuth, analyticsRateLimitMiddleware, async (req, res) => {
    try {
      const { sessionId, durationMs, didWin, score, difficulty } = req.body || {};
      if (!Number.isInteger(sessionId) || sessionId <= 0) {
        return res.status(400).json({ error: 'Invalid sessionId' });
      }
      if (!Number.isInteger(durationMs) || durationMs < 0) {
        return res.status(400).json({ error: 'Invalid durationMs' });
      }
      if (typeof didWin !== 'boolean') {
        return res.status(400).json({ error: 'Invalid didWin' });
      }
      if (!Number.isInteger(score) || score < 0) {
        return res.status(400).json({ error: 'Invalid score' });
      }
      if (!['easy', 'normal', 'hard'].includes(difficulty)) {
        return res.status(400).json({ error: 'Invalid difficulty' });
      }
      const safeDurationMs = Math.min(durationMs, 1000 * 60 * 60 * 6);
      const sql = `
        UPDATE game_sessions
        SET ended_at = NOW(),
            duration_ms = $3,
            did_win = $4,
            score = $5,
            difficulty = $6
        WHERE id = $1
          AND user_id = $2
          AND ended_at IS NULL
        RETURNING id
      `;
      const result = await pool.query(sql, [sessionId, req.user.id, safeDurationMs, didWin, score, difficulty]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Session not found' });
      }
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ error: 'Failed to end session' });
    }
  });

  app.get('/admin/overview', adminRateLimitMiddleware, requireAdmin, async (_req, res) => {
    try {
      const sql = `
        SELECT
          (SELECT COUNT(*)::int FROM users) AS total_users,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN ended_at IS NOT NULL OR duration_ms IS NOT NULL THEN 1
                  ELSE 0
                END
              ),
              0
            )::int
            FROM game_sessions
          ) AS total_games,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN duration_ms IS NOT NULL THEN duration_ms
                  WHEN ended_at IS NOT NULL THEN GREATEST(
                    0,
                    FLOOR(EXTRACT(EPOCH FROM (ended_at - started_at)) * 1000)
                  )::int
                  ELSE 0
                END
              ),
              0
            )::bigint
            FROM game_sessions
          ) AS total_play_time_ms,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN (ended_at IS NOT NULL OR duration_ms IS NOT NULL) AND did_win THEN 1
                  ELSE 0
                END
              ),
              0
            )::int
            FROM game_sessions
          ) AS total_wins
      `;
      const result = await pool.query(sql);
      return res.json(result.rows[0] || {
        total_users: 0,
        total_games: 0,
        total_play_time_ms: 0,
        total_wins: 0,
      });
    } catch {
      return res.status(500).json({ error: 'Failed to fetch overview' });
    }
  });

  app.get('/admin/users', adminRateLimitMiddleware, requireAdmin, async (req, res) => {
    try {
      const parsedLimit = Number.parseInt(req.query.limit || '100', 10);
      const limit = Number.isFinite(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 500) : 100;
      const sql = `
        SELECT
          u.id,
          u.username,
          u.created_at,
          COALESCE(gs_agg.total_play_time_ms, 0)::bigint AS total_play_time_ms,
          COALESCE(gs_agg.games_played, 0)::int AS games_played,
          COALESCE(gs_agg.games_won, 0)::int AS games_won,
          gs_agg.last_played_at,
          s_agg.best_score
        FROM users u
        LEFT JOIN (
          SELECT
            user_id,
            COALESCE(
              SUM(
                CASE
                  WHEN duration_ms IS NOT NULL THEN duration_ms
                  WHEN ended_at IS NOT NULL THEN GREATEST(
                    0,
                    FLOOR(EXTRACT(EPOCH FROM (ended_at - started_at)) * 1000)
                  )::int
                  ELSE 0
                END
              ),
              0
            )::bigint AS total_play_time_ms,
            COALESCE(
              SUM(
                CASE
                  WHEN ended_at IS NOT NULL OR duration_ms IS NOT NULL THEN 1
                  ELSE 0
                END
              ),
              0
            )::int AS games_played,
            COALESCE(
              SUM(
                CASE
                  WHEN (ended_at IS NOT NULL OR duration_ms IS NOT NULL) AND did_win THEN 1
                  ELSE 0
                END
              ),
              0
            )::int AS games_won,
            MAX(ended_at) AS last_played_at
          FROM game_sessions
          GROUP BY user_id
        ) gs_agg ON gs_agg.user_id = u.id
        LEFT JOIN (
          SELECT user_id, MAX(score)::int AS best_score
          FROM scores
          GROUP BY user_id
        ) s_agg ON s_agg.user_id = u.id
        ORDER BY u.username_norm ASC, u.created_at DESC
        LIMIT $1
      `;
      const result = await pool.query(sql, [limit]);
      return res.json(result.rows);
    } catch {
      return res.status(500).json({ error: 'Failed to fetch users stats' });
    }
  });

  app.get('/admin/dashboard', adminRateLimitMiddleware, requireAdmin, async (req, res) => {
    try {
      const parsedLimit = Number.parseInt(req.query.limit || '200', 10);
      const limit = Number.isFinite(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 500) : 200;

      const overviewSql = `
        SELECT
          (SELECT COUNT(*)::int FROM users) AS total_users,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN ended_at IS NOT NULL OR duration_ms IS NOT NULL THEN 1
                  ELSE 0
                END
              ),
              0
            )::int
            FROM game_sessions
          ) AS total_games,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN duration_ms IS NOT NULL THEN duration_ms
                  WHEN ended_at IS NOT NULL THEN GREATEST(
                    0,
                    FLOOR(EXTRACT(EPOCH FROM (ended_at - started_at)) * 1000)
                  )::int
                  ELSE 0
                END
              ),
              0
            )::bigint
            FROM game_sessions
          ) AS total_play_time_ms,
          (
            SELECT COALESCE(
              SUM(
                CASE
                  WHEN (ended_at IS NOT NULL OR duration_ms IS NOT NULL) AND did_win THEN 1
                  ELSE 0
                END
              ),
              0
            )::int
            FROM game_sessions
          ) AS total_wins
      `;
      const usersSql = `
        SELECT
          u.id,
          u.username,
          u.created_at,
          COALESCE(gs_agg.total_play_time_ms, 0)::bigint AS total_play_time_ms,
          COALESCE(gs_agg.games_played, 0)::int AS games_played,
          COALESCE(gs_agg.games_won, 0)::int AS games_won,
          gs_agg.last_played_at,
          s_agg.best_score
        FROM users u
        LEFT JOIN (
          SELECT
            user_id,
            COALESCE(
              SUM(
                CASE
                  WHEN duration_ms IS NOT NULL THEN duration_ms
                  WHEN ended_at IS NOT NULL THEN GREATEST(
                    0,
                    FLOOR(EXTRACT(EPOCH FROM (ended_at - started_at)) * 1000)
                  )::int
                  ELSE 0
                END
              ),
              0
            )::bigint AS total_play_time_ms,
            COALESCE(
              SUM(
                CASE
                  WHEN ended_at IS NOT NULL OR duration_ms IS NOT NULL THEN 1
                  ELSE 0
                END
              ),
              0
            )::int AS games_played,
            COALESCE(
              SUM(
                CASE
                  WHEN (ended_at IS NOT NULL OR duration_ms IS NOT NULL) AND did_win THEN 1
                  ELSE 0
                END
              ),
              0
            )::int AS games_won,
            MAX(ended_at) AS last_played_at
          FROM game_sessions
          GROUP BY user_id
        ) gs_agg ON gs_agg.user_id = u.id
        LEFT JOIN (
          SELECT user_id, MAX(score)::int AS best_score
          FROM scores
          GROUP BY user_id
        ) s_agg ON s_agg.user_id = u.id
        ORDER BY u.username_norm ASC, u.created_at DESC
        LIMIT $1
      `;

      const [overviewResult, usersResult] = await Promise.all([
        pool.query(overviewSql),
        pool.query(usersSql, [limit]),
      ]);

      return res.json({
        overview: overviewResult.rows[0] || {
          total_users: 0,
          total_games: 0,
          total_play_time_ms: 0,
          total_wins: 0,
        },
        users: usersResult.rows || [],
      });
    } catch {
      return res.status(500).json({ error: 'Failed to fetch dashboard' });
    }
  });

  app.get('/admin/traffic-week', adminRateLimitMiddleware, requireAdmin, async (_req, res) => {
    try {
      const sql = `
        WITH day_buckets AS (
          SELECT generate_series(
            (CURRENT_DATE - INTERVAL '6 days')::date,
            CURRENT_DATE::date,
            INTERVAL '1 day'
          ) AS day_start
        )
        SELECT
          db.day_start::date AS day,
          COUNT(gs.*)::int AS sessions,
          COUNT(DISTINCT gs.user_id)::int AS users
        FROM day_buckets db
        LEFT JOIN game_sessions gs
          ON gs.started_at >= db.day_start
         AND gs.started_at < (db.day_start + INTERVAL '1 day')
        GROUP BY db.day_start
        ORDER BY db.day_start ASC
      `;
      const result = await pool.query(sql);
      return res.json(Array.isArray(result.rows) ? result.rows : []);
    } catch {
      return res.status(500).json({ error: 'Failed to fetch weekly traffic' });
    }
  });

  app.delete('/scores', adminRateLimitMiddleware, requireAdmin, requireAdminToken, async (req, res) => {
    try {
      await pool.query('DELETE FROM scores');
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ error: 'Failed to reset scores' });
    }
  });

  app.delete('/admin/statistics', adminRateLimitMiddleware, requireAdmin, requireAdminToken, async (_req, res) => {
    try {
      const result = await pool.query('DELETE FROM game_sessions');
      return res.json({ ok: true, deleted: result.rowCount || 0 });
    } catch {
      return res.status(500).json({ error: 'Failed to reset statistics' });
    }
  });

  app.delete('/admin/users/:userId', adminRateLimitMiddleware, requireAdmin, requireAdminToken, async (req, res) => {
    try {
      const userId = Number.parseInt(req.params.userId, 10);
      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid user id' });
      }
      if (req.user?.id === userId) {
        return res.status(400).json({ error: 'Cannot delete your own admin account' });
      }
      const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, username', [userId]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.json({ ok: true, deleted_user: result.rows[0] });
    } catch {
      return res.status(500).json({ error: 'Failed to delete user' });
    }
  });

  app.use((err, _req, res, next) => {
    if (err?.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Payload too large' });
    }
    if (err instanceof SyntaxError && 'body' in err) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
    return next(err);
  });
  app.use((err, _req, res, _next) => {
    console.error('Unhandled server error:', err?.message || err);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

async function startServer() {
  const adminResetToken = String(process.env.ADMIN_RESET_TOKEN || '');
  const insecureToken =
    adminResetToken.length < 16 ||
    adminResetToken.toLowerCase().includes('change-me');
  if (insecureToken) {
    throw new Error('ADMIN_RESET_TOKEN is missing or too weak. Set a strong token (min 16 chars).');
  }
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });
  const rateLimitStore = String(process.env.RATE_LIMIT_STORE || 'memory').trim().toLowerCase();
  const requireRateLimitTable = rateLimitStore === 'database';
  const autoMigrateOnStart = parseBoolean(process.env.AUTO_MIGRATE_ON_START, false);
  if (autoMigrateOnStart) {
    await ensureSchema(pool);
  } else {
    const schemaReady = await hasRequiredSchema(pool, { requireRateLimitTable });
    if (!schemaReady) {
      throw new Error('Database schema is missing. Run server/db/schema.sql or set AUTO_MIGRATE_ON_START=true for first boot.');
    }
  }
  await pool.query('SELECT 1 AS ok');
  const app = createApp({ pool });
  const port = process.env.PORT || 3001;
  app.listen(port, () => {
    console.log(`Server listening on ${port}`);
  });
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  startServer().catch((err) => {
    console.error('Failed to start server:', err?.message || err);
    process.exit(1);
  });
}

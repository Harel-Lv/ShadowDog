import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const { Pool } = pkg;
const DEFAULT_CORS_ORIGINS = 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000,http://127.0.0.1:3000';
const PASSWORD_MIN_LENGTH = 6;
const PASSWORD_MAX_LENGTH = 128;
const DEFAULT_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
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

function normalizeUsername(username) {
  return typeof username === 'string' ? username.trim().toLowerCase() : '';
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

function createInMemoryRateLimiter({
  max,
  windowMs,
  keyFn,
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

  return (req, res, next) => {
    const now = Date.now();
    cleanup(now);
    const key = keyFn(req);
    const current = state.get(key);
    if (!current || now - current.windowStart >= windowMs) {
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

export function createApp({
  pool,
  adminResetToken = process.env.ADMIN_RESET_TOKEN,
  corsOrigins = process.env.CORS_ORIGINS || DEFAULT_CORS_ORIGINS,
  scoreRateLimitMax = parsePositiveInt(process.env.SCORE_RATE_LIMIT_MAX, 30),
  scoreRateLimitWindowMs = parsePositiveInt(process.env.SCORE_RATE_LIMIT_WINDOW_MS, 60000),
  adminRateLimitMax = parsePositiveInt(process.env.ADMIN_RATE_LIMIT_MAX, 5),
  adminRateLimitWindowMs = parsePositiveInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS, 60000),
  authRateLimitMax = parsePositiveInt(process.env.AUTH_RATE_LIMIT_MAX, 10),
  authRateLimitWindowMs = parsePositiveInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 60000),
  sessionTtlMs = parsePositiveInt(process.env.SESSION_TTL_MS, DEFAULT_SESSION_TTL_MS),
  trustProxy = parseBoolean(process.env.TRUST_PROXY, false),
} = {}) {
  if (!pool || typeof pool.query !== 'function') {
    throw new Error('A database pool with a query method is required');
  }

  const allowedOrigins = corsOrigins
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

  const app = express();
  app.set('trust proxy', trustProxy);
  app.use(cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
  }));
  app.use(express.json());

  const scoreRateLimitMiddleware = createInMemoryRateLimiter({
    max: scoreRateLimitMax,
    windowMs: scoreRateLimitWindowMs,
    keyFn: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  });
  const authRateLimitMiddleware = createInMemoryRateLimiter({
    max: authRateLimitMax,
    windowMs: authRateLimitWindowMs,
    keyFn: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  });
  const adminRateLimitMiddleware = createInMemoryRateLimiter({
    max: adminRateLimitMax,
    windowMs: adminRateLimitWindowMs,
    keyFn: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
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

  async function requireAuth(req, res, next) {
    const authHeader = req.get('authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
      await cleanupExpiredSessions();
      const sql = `
        SELECT u.id, u.username, us.token
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

  app.get('/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/auth/signup', authRateLimitMiddleware, async (req, res) => {
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
      return res.status(201).json({ token, user });
    } catch (err) {
      if (err?.code === '23505') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Failed to signup' });
    }
  });

  app.post('/auth/login', authRateLimitMiddleware, async (req, res) => {
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
      return res.json({ token, user });
    } catch {
      return res.status(500).json({ error: 'Failed to login' });
    }
  });

  app.post('/auth/logout', requireAuth, async (req, res) => {
    try {
      await pool.query('DELETE FROM user_sessions WHERE token = $1', [req.token]);
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

  app.delete('/scores', adminRateLimitMiddleware, async (req, res) => {
    const providedToken = req.get('x-admin-token');
    if (!adminResetToken || providedToken !== adminResetToken) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    try {
      await pool.query('DELETE FROM scores');
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ error: 'Failed to reset scores' });
    }
  });

  return app;
}

function startServer() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });
  const app = createApp({ pool });
  const port = process.env.PORT || 3001;
  app.listen(port, () => {
    console.log(`Server listening on ${port}`);
  });
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) startServer();

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from './index.js';

class FakePool {
  constructor() {
    this.scores = [];
    this.users = [];
    this.sessions = [];
    this.nextScoreId = 1;
    this.nextUserId = 1;
    this.healthShouldFail = false;
  }

  async query(sql, params = []) {
    const normalizedSql = sql.replace(/\s+/g, ' ').trim();

    if (normalizedSql.startsWith('SELECT u.id, u.username, u.username_norm, us.token FROM user_sessions us JOIN users u ON u.id = us.user_id WHERE us.token = $1')) {
      const token = params[0];
      const session = this.sessions.find(s => s.token === token);
      if (!session) return { rows: [] };
      if (new Date(session.expires_at).getTime() <= Date.now()) return { rows: [] };
      const user = this.users.find(u => u.id === session.user_id);
      if (!user) return { rows: [] };
      return { rows: [{ id: user.id, username: user.username, username_norm: user.username_norm, token: session.token }] };
    }

    if (normalizedSql === 'SELECT 1 AS ok') {
      if (this.healthShouldFail) throw new Error('health check failed');
      return { rows: [{ ok: 1 }] };
    }

    if (normalizedSql.startsWith('INSERT INTO users (username, username_norm, password_hash) VALUES ($1, $2, $3) RETURNING id, username')) {
      const [username, usernameNorm, passwordHash] = params;
      if (this.users.some(u => u.username_norm === usernameNorm)) {
        const err = new Error('duplicate key');
        err.code = '23505';
        throw err;
      }
      const user = {
        id: this.nextUserId++,
        username,
        username_norm: usernameNorm,
        password_hash: passwordHash,
      };
      this.users.push(user);
      return { rows: [{ id: user.id, username: user.username }] };
    }

    if (normalizedSql === 'SELECT id, username, password_hash FROM users WHERE username_norm = $1') {
      const usernameNorm = params[0];
      const user = this.users.find(u => u.username_norm === usernameNorm);
      return { rows: user ? [{ id: user.id, username: user.username, password_hash: user.password_hash }] : [] };
    }

    if (normalizedSql === 'INSERT INTO user_sessions (token, user_id, expires_at) VALUES ($1, $2, $3)') {
      const [token, userId, expiresAt] = params;
      this.sessions.push({ token, user_id: userId, expires_at: expiresAt });
      return { rows: [] };
    }

    if (normalizedSql === 'DELETE FROM user_sessions WHERE token = $1') {
      const token = params[0];
      this.sessions = this.sessions.filter(s => s.token !== token);
      return { rows: [] };
    }

    if (normalizedSql === 'DELETE FROM user_sessions WHERE expires_at <= NOW()') {
      const now = Date.now();
      this.sessions = this.sessions.filter(s => new Date(s.expires_at).getTime() > now);
      return { rows: [] };
    }

    if (normalizedSql.startsWith('SELECT name, score, difficulty, created_at FROM scores')) {
      const hasDifficulty = normalizedSql.includes('WHERE difficulty = $1');
      const difficulty = hasDifficulty ? params[0] : null;
      const limit = params[params.length - 1];
      let filtered = this.scores.slice();
      if (difficulty) filtered = filtered.filter(row => row.difficulty === difficulty);
      filtered.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        return a.created_at.localeCompare(b.created_at);
      });
      return { rows: filtered.slice(0, limit) };
    }

    if (normalizedSql.startsWith('INSERT INTO scores (user_id, name, score, difficulty) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, difficulty)')) {
      const [userId, name, score, difficulty] = params;
      const existing = this.scores.find(row => row.user_id === userId && row.difficulty === difficulty);
      if (existing) {
        if (score > existing.score) {
          existing.score = score;
          existing.name = name;
          existing.created_at = new Date().toISOString();
          return { rows: [{ ...existing }] };
        }
        return { rows: [] };
      }
      const row = {
        id: this.nextScoreId++,
        user_id: userId,
        name,
        score,
        difficulty,
        created_at: new Date().toISOString(),
      };
      this.scores.push(row);
      return { rows: [{ ...row }] };
    }

    if (normalizedSql === 'DELETE FROM scores') {
      this.scores = [];
      return { rows: [] };
    }

    throw new Error(`Unexpected SQL in test: ${normalizedSql}`);
  }
}

function sendJson({ port, method, path, headers = {}, body }) {
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try {
          parsed = data ? JSON.parse(data) : null;
        } catch {
          parsed = data;
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function withServer(optionsOrRun, maybeRun) {
  const options = typeof maybeRun === 'function' ? optionsOrRun : {};
  const run = typeof maybeRun === 'function' ? maybeRun : optionsOrRun;

  const pool = new FakePool();
  const app = createApp({
    pool,
    adminResetToken: 'test-token',
    adminUsername: 'admin',
    corsOrigins: 'http://localhost:5500',
    ...options,
  });
  const server = await new Promise(resolve => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  try {
    await run({ pool, port });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('signup creates account and returns token', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    assert.equal(res.status, 201);
    assert.equal(typeof res.body.token, 'string');
    assert.equal(res.body.user.username, 'Player1');
  });
});

test('GET /health returns 500 when database is unavailable', async () => {
  await withServer(async ({ port, pool }) => {
    pool.healthShouldFail = true;
    const res = await sendJson({
      port,
      method: 'GET',
      path: '/health',
    });
    assert.equal(res.status, 500);
    assert.deepEqual(res.body, { ok: false, db: false });
  });
});

test('signup rejects duplicate username', async () => {
  await withServer(async ({ port }) => {
    const first = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    assert.equal(first.status, 201);

    const second = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'player1', password: 'secret123' },
    });
    assert.equal(second.status, 409);
  });
});

test('signup rejects passwords longer than max length', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'a'.repeat(129) },
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Password must be at most 128 characters' });
  });
});

test('signup validates missing username with explicit message', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { password: 'secret123' },
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Username is required' });
  });
});

test('signup validates short password with explicit message', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: '123' },
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Password must be at least 6 characters' });
  });
});

test('login returns token for valid credentials', async () => {
  await withServer(async ({ port }) => {
    await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const login = await sendJson({
      port,
      method: 'POST',
      path: '/auth/login',
      body: { username: 'player1', password: 'secret123' },
    });
    assert.equal(login.status, 200);
    assert.equal(typeof login.body.token, 'string');
  });
});

test('logout invalidates session token', async () => {
  await withServer(async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = signup.body.token;

    const beforeLogout = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: 7, difficulty: 'easy' },
    });
    assert.equal(beforeLogout.status, 201);

    const logout = await sendJson({
      port,
      method: 'POST',
      path: '/auth/logout',
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(logout.status, 200);

    const afterLogout = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: 9, difficulty: 'easy' },
    });
    assert.equal(afterLogout.status, 401);
  });
});

test('POST /scores requires authentication', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      body: { score: 5, difficulty: 'easy' },
    });
    assert.equal(res.status, 401);
  });
});

test('POST /scores rejects negative score for authenticated user', async () => {
  await withServer(async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = signup.body.token;
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: -1, difficulty: 'easy' },
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Invalid score' });
  });
});

test('POST /scores returns 429 when rate limit exceeded', async () => {
  await withServer({ scoreRateLimitMax: 1, scoreRateLimitWindowMs: 60000 }, async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = signup.body.token;

    const first = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: 1, difficulty: 'easy' },
    });
    assert.equal(first.status, 201);

    const second = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: 2, difficulty: 'easy' },
    });
    assert.equal(second.status, 429);
  });
});

test('GET /scores keeps stable ordering on score ties by created_at asc', async () => {
  await withServer(async ({ port, pool }) => {
    const signupA = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Alpha', password: 'secret123' },
    });
    const signupB = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Bravo', password: 'secret123' },
    });

    await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${signupA.body.token}` },
      body: { score: 50, difficulty: 'easy' },
    });
    await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${signupB.body.token}` },
      body: { score: 50, difficulty: 'easy' },
    });

    const alphaRow = pool.scores.find(row => row.name === 'Alpha');
    const bravoRow = pool.scores.find(row => row.name === 'Bravo');
    alphaRow.created_at = '2026-01-01T00:00:00.000Z';
    bravoRow.created_at = '2026-01-01T00:00:01.000Z';

    const res = await sendJson({
      port,
      method: 'GET',
      path: '/scores?difficulty=easy&limit=10',
    });
    assert.equal(res.status, 200);
    assert.equal(res.body[0].name, 'Alpha');
    assert.equal(res.body[1].name, 'Bravo');
  });
});

test('DELETE /scores requires admin authentication', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({ port, method: 'DELETE', path: '/scores' });
    assert.equal(res.status, 401);
  });
});

test('DELETE /scores requires admin token even for authenticated admin', async () => {
  await withServer(async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = signup.body.token;
    const forbidden = await sendJson({
      port,
      method: 'DELETE',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(forbidden.status, 403);
  });
});

test('DELETE /scores returns 403 for authenticated non-admin user', async () => {
  await withServer(async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'player1', password: 'secret123' },
    });
    const token = signup.body.token;
    const forbidden = await sendJson({
      port,
      method: 'DELETE',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}`, 'x-admin-token': 'test-token' },
    });
    assert.equal(forbidden.status, 403);
  });
});

test('DELETE /scores succeeds for authenticated admin with valid token', async () => {
  await withServer(async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = signup.body.token;

    const save = await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
      body: { score: 99, difficulty: 'easy' },
    });
    assert.equal(save.status, 201);

    const reset = await sendJson({
      port,
      method: 'DELETE',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}`, 'x-admin-token': 'test-token' },
    });
    assert.equal(reset.status, 200);
    assert.deepEqual(reset.body, { ok: true });

    const after = await sendJson({
      port,
      method: 'GET',
      path: '/scores?difficulty=easy&limit=10',
    });
    assert.equal(after.status, 200);
    assert.equal(after.body.length, 0);
  });
});

test('DELETE /scores returns 429 when admin rate limit exceeded', async () => {
  await withServer({ adminRateLimitMax: 1, adminRateLimitWindowMs: 60000 }, async ({ port }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = signup.body.token;
    const first = await sendJson({
      port,
      method: 'DELETE',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(first.status, 403);

    const second = await sendJson({
      port,
      method: 'DELETE',
      path: '/scores',
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(second.status, 429);
  });
});

test('auth endpoints return 429 when auth rate limit exceeded', async () => {
  await withServer({ authRateLimitMax: 1, authRateLimitWindowMs: 60000 }, async ({ port }) => {
    const first = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    assert.equal(first.status, 201);

    const second = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player2', password: 'secret123' },
    });
    assert.equal(second.status, 429);
  });
});

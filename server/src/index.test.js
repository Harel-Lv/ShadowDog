import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from './index.js';

class FakePool {
  constructor() {
    this.scores = [];
    this.users = [];
    this.sessions = [];
    this.gameSessions = [];
    this.nextScoreId = 1;
    this.nextUserId = 1;
    this.nextGameSessionId = 1;
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
        created_at: new Date().toISOString(),
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

    if (normalizedSql.startsWith('INSERT INTO game_sessions (user_id, started_at) VALUES ($1, NOW()) RETURNING id, started_at')) {
      const userId = params[0];
      const row = {
        id: this.nextGameSessionId++,
        user_id: userId,
        started_at: new Date().toISOString(),
        ended_at: null,
        duration_ms: null,
        did_win: null,
        score: null,
        difficulty: null,
      };
      this.gameSessions.push(row);
      return { rows: [{ id: row.id, started_at: row.started_at }] };
    }

    if (normalizedSql.startsWith('UPDATE game_sessions SET ended_at = NOW(), duration_ms = $3, did_win = $4, score = $5, difficulty = $6 WHERE id = $1 AND user_id = $2 AND ended_at IS NULL RETURNING id')) {
      const [sessionId, userId, durationMs, didWin, score, difficulty] = params;
      const row = this.gameSessions.find(s => s.id === sessionId && s.user_id === userId && s.ended_at === null);
      if (!row) return { rows: [] };
      row.ended_at = new Date().toISOString();
      row.duration_ms = durationMs;
      row.did_win = didWin;
      row.score = score;
      row.difficulty = difficulty;
      return { rows: [{ id: row.id }] };
    }

    if (normalizedSql === 'DELETE FROM game_sessions') {
      const deleted = this.gameSessions.length;
      this.gameSessions = [];
      return { rows: [], rowCount: deleted };
    }

    if (normalizedSql === 'DELETE FROM users WHERE id = $1 RETURNING id, username') {
      const userId = params[0];
      const user = this.users.find(u => u.id === userId);
      if (!user) return { rows: [] };
      this.users = this.users.filter(u => u.id !== userId);
      this.sessions = this.sessions.filter(s => s.user_id !== userId);
      this.gameSessions = this.gameSessions.filter(gs => gs.user_id !== userId);
      this.scores = this.scores.filter(sc => sc.user_id !== userId);
      return { rows: [{ id: user.id, username: user.username }] };
    }

    if (
      normalizedSql.includes('AS total_users') &&
      normalizedSql.includes('AS total_games') &&
      normalizedSql.includes('AS total_play_time_ms') &&
      normalizedSql.includes('AS total_wins')
    ) {
      const completed = this.gameSessions.filter(s => s.ended_at !== null || s.duration_ms !== null);
      const totalPlayTime = completed.reduce((sum, s) => sum + Math.max(0, Number(s.duration_ms || 0)), 0);
      const totalWins = completed.reduce((sum, s) => sum + (s.did_win ? 1 : 0), 0);
      return {
        rows: [{
          total_users: this.users.length,
          total_games: completed.length,
          total_play_time_ms: totalPlayTime,
          total_wins: totalWins,
        }],
      };
    }

    if (
      normalizedSql.includes('FROM users u') &&
      normalizedSql.includes('AS total_play_time_ms') &&
      normalizedSql.includes('AS games_played') &&
      normalizedSql.includes('AS games_won') &&
      normalizedSql.includes('AS best_score') &&
      normalizedSql.includes('LIMIT $1')
    ) {
      const limit = params[0] ?? 100;
      const rows = this.users.map((u) => {
        const sessions = this.gameSessions.filter(s => s.user_id === u.id);
        const completed = sessions.filter(s => s.ended_at !== null || s.duration_ms !== null);
        const totalPlayTime = completed.reduce((sum, s) => sum + Math.max(0, Number(s.duration_ms || 0)), 0);
        const gamesWon = completed.reduce((sum, s) => sum + (s.did_win ? 1 : 0), 0);
        const endedAtValues = sessions
          .map(s => s.ended_at)
          .filter(Boolean)
          .sort((a, b) => String(a).localeCompare(String(b)));
        const userBestScore = this.scores
          .filter(sc => sc.user_id === u.id)
          .reduce((max, sc) => Math.max(max, Number(sc.score || 0)), 0);
        return {
          id: u.id,
          username: u.username,
          created_at: u.created_at,
          total_play_time_ms: totalPlayTime,
          games_played: completed.length,
          games_won: gamesWon,
          last_played_at: endedAtValues.length ? endedAtValues[endedAtValues.length - 1] : null,
          best_score: userBestScore || null,
          username_norm: u.username_norm,
        };
      });
      rows.sort((a, b) => {
        const byName = String(a.username_norm).localeCompare(String(b.username_norm));
        if (byName !== 0) return byName;
        return String(b.created_at).localeCompare(String(a.created_at));
      });
      const sanitized = rows.slice(0, limit).map(({ username_norm, ...rest }) => rest);
      return { rows: sanitized };
    }

    if (
      normalizedSql.includes('FROM day_buckets db') &&
      normalizedSql.includes('COUNT(gs.*)::int AS sessions') &&
      normalizedSql.includes('COUNT(DISTINCT gs.user_id)::int AS users')
    ) {
      const days = Number(params[0] || 7);
      const rows = Array.from({ length: days }, (_, i) => ({
        day: new Date(Date.now() - ((days - 1 - i) * 24 * 60 * 60 * 1000)).toISOString(),
        sessions: 0,
        users: 0,
      }));
      return { rows };
    }

    if (
      normalizedSql.includes('sessions_by_hour AS') &&
      normalizedSql.includes('hour_buckets AS') &&
      normalizedSql.includes('COALESCE(sh.sessions, 0)::int AS sessions')
    ) {
      const rows = Array.from({ length: 24 }, (_, hour) => ({
        hour,
        sessions: 0,
        users: 0,
      }));
      return { rows };
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

function latestTokenForUser(pool, userId) {
  const sessions = pool.sessions.filter((s) => s.user_id === userId);
  return sessions.length ? sessions[sessions.length - 1].token : '';
}

test('signup creates account and returns user', async () => {
  await withServer(async ({ port }) => {
    const res = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    assert.equal(res.status, 201);
    assert.equal(typeof res.body.user.id, 'number');
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

test('login returns user for valid credentials', async () => {
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
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
    assert.equal(login.body.user.username, 'Player1');
    const token = latestTokenForUser(pool, signup.body.user.id);
    assert.equal(typeof token, 'string');
    assert.ok(token.length > 0);
  });
});

test('logout invalidates session token', async () => {
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);

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
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);
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
  await withServer({ scoreRateLimitMax: 1, scoreRateLimitWindowMs: 60000 }, async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);

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

    const signupAToken = latestTokenForUser(pool, signupA.body.user.id);
    const signupBToken = latestTokenForUser(pool, signupB.body.user.id);
    await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${signupAToken}` },
      body: { score: 50, difficulty: 'easy' },
    });
    await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${signupBToken}` },
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
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);
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
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'player1', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);
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
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);

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
  await withServer({ adminRateLimitMax: 1, adminRateLimitWindowMs: 60000 }, async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);
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

test('analytics session start/end flow updates admin dashboard metrics', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const started = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/start',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(started.status, 201);
    assert.equal(typeof started.body.id, 'number');

    const ended = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/end',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        sessionId: started.body.id,
        durationMs: 12345,
        didWin: true,
        score: 10,
        difficulty: 'easy',
      },
    });
    assert.equal(ended.status, 200);
    assert.deepEqual(ended.body, { ok: true });

    const dashboard = await sendJson({
      port,
      method: 'GET',
      path: '/admin/dashboard?limit=10',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(dashboard.status, 200);
    assert.equal(dashboard.body.overview.total_games, 1);
    assert.equal(dashboard.body.overview.total_wins, 1);
    assert.equal(dashboard.body.overview.total_play_time_ms, 12345);
    assert.equal(dashboard.body.users[0].games_played, 1);
    assert.equal(dashboard.body.users[0].games_won, 1);
    assert.equal(dashboard.body.users[0].total_play_time_ms, 12345);
  });
});

test('analytics end rejects invalid session id', async () => {
  await withServer(async ({ port, pool }) => {
    const signup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'Player1', password: 'secret123' },
    });
    const token = latestTokenForUser(pool, signup.body.user.id);

    const ended = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/end',
      headers: { Authorization: `Bearer ${token}` },
      body: {
        sessionId: -1,
        durationMs: 1000,
        didWin: false,
        score: 0,
        difficulty: 'easy',
      },
    });
    assert.equal(ended.status, 400);
    assert.deepEqual(ended.body, { error: 'Invalid sessionId' });
  });
});

test('DELETE /admin/statistics requires admin token and clears sessions', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const started = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/start',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/end',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        sessionId: started.body.id,
        durationMs: 2000,
        didWin: false,
        score: 1,
        difficulty: 'normal',
      },
    });

    const forbidden = await sendJson({
      port,
      method: 'DELETE',
      path: '/admin/statistics',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(forbidden.status, 403);

    const allowed = await sendJson({
      port,
      method: 'DELETE',
      path: '/admin/statistics',
      headers: { Authorization: `Bearer ${adminToken}`, 'x-admin-token': 'test-token' },
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body.ok, true);
    assert.equal(allowed.body.deleted, 1);

    const dashboard = await sendJson({
      port,
      method: 'GET',
      path: '/admin/dashboard?limit=10',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(dashboard.status, 200);
    assert.equal(dashboard.body.overview.total_games, 0);
    assert.equal(dashboard.body.overview.total_play_time_ms, 0);
  });
});

test('admin per-user games and wins count only completed sessions', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const startedOpen = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/start',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(startedOpen.status, 201);

    const startedClosed = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/start',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(startedClosed.status, 201);

    const ended = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/end',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        sessionId: startedClosed.body.id,
        durationMs: 3000,
        didWin: true,
        score: 5,
        difficulty: 'hard',
      },
    });
    assert.equal(ended.status, 200);

    const users = await sendJson({
      port,
      method: 'GET',
      path: '/admin/users?limit=10',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(users.status, 200);
    const adminRow = users.body.find((u) => u.username === 'admin');
    assert.ok(adminRow);
    assert.equal(adminRow.games_played, 1);
    assert.equal(adminRow.games_won, 1);
    assert.equal(adminRow.total_play_time_ms, 3000);
  });
});

test('DELETE /admin/users/:id deletes user and cascades scores/statistics', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const playerSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'player1', password: 'secret123' },
    });
    const playerToken = latestTokenForUser(pool, playerSignup.body.user.id);
    const playerId = playerSignup.body.user.id;

    await sendJson({
      port,
      method: 'POST',
      path: '/scores',
      headers: { Authorization: `Bearer ${playerToken}` },
      body: { score: 42, difficulty: 'easy' },
    });
    const started = await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/start',
      headers: { Authorization: `Bearer ${playerToken}` },
    });
    await sendJson({
      port,
      method: 'POST',
      path: '/analytics/session/end',
      headers: { Authorization: `Bearer ${playerToken}` },
      body: {
        sessionId: started.body.id,
        durationMs: 5000,
        didWin: true,
        score: 42,
        difficulty: 'easy',
      },
    });

    const deleted = await sendJson({
      port,
      method: 'DELETE',
      path: `/admin/users/${playerId}`,
      headers: { Authorization: `Bearer ${adminToken}`, 'x-admin-token': 'test-token' },
    });
    assert.equal(deleted.status, 200);
    assert.equal(deleted.body.ok, true);
    assert.equal(deleted.body.deleted_user.id, playerId);

    const dashboard = await sendJson({
      port,
      method: 'GET',
      path: '/admin/dashboard?limit=10',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(dashboard.status, 200);
    assert.equal(dashboard.body.users.some((u) => u.username === 'player1'), false);
  });
});

test('DELETE /admin/users/:id rejects deleting own admin account', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);
    const adminId = adminSignup.body.user.id;

    const res = await sendJson({
      port,
      method: 'DELETE',
      path: `/admin/users/${adminId}`,
      headers: { Authorization: `Bearer ${adminToken}`, 'x-admin-token': 'test-token' },
    });
    assert.equal(res.status, 400);
    assert.deepEqual(res.body, { error: 'Cannot delete your own admin account' });
  });
});

test('GET /admin/traffic supports 30 days range for admin', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const traffic = await sendJson({
      port,
      method: 'GET',
      path: '/admin/traffic?days=30&tz_offset_min=-120',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(traffic.status, 200);
    assert.ok(Array.isArray(traffic.body));
    assert.equal(traffic.body.length, 30);
  });
});

test('GET /admin/active-hours returns 24 buckets for admin', async () => {
  await withServer(async ({ port, pool }) => {
    const adminSignup = await sendJson({
      port,
      method: 'POST',
      path: '/auth/signup',
      body: { username: 'admin', password: 'secret123' },
    });
    const adminToken = latestTokenForUser(pool, adminSignup.body.user.id);

    const hours = await sendJson({
      port,
      method: 'GET',
      path: '/admin/active-hours?tz_offset_min=180',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(hours.status, 200);
    assert.ok(Array.isArray(hours.body));
    assert.equal(hours.body.length, 24);
    assert.deepEqual(hours.body[0], { hour: 0, sessions: 0, users: 0 });
    assert.deepEqual(hours.body[23], { hour: 23, sessions: 0, users: 0 });
  });
});

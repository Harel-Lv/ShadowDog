import { test, expect } from '@playwright/test';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientRoot = path.resolve(__dirname, '../../client');

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.js') return 'application/javascript; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.json') return 'application/json; charset=utf-8';
  if (ext === '.png') return 'image/png';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  if (ext === '.ogg') return 'audio/ogg';
  return 'application/octet-stream';
}

async function startStaticServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const rawPath = String(req.url || '/').split('?')[0] || '/';
      const normalized = rawPath === '/' ? '/game.html' : rawPath;
      const safePath = path.normalize(normalized).replace(/^(\.\.[/\\])+/, '');
      const fullPath = path.resolve(clientRoot, `.${safePath}`);
      if (!fullPath.startsWith(clientRoot)) {
        res.statusCode = 403;
        res.end('Forbidden');
        return;
      }
      const data = await fs.readFile(fullPath);
      res.statusCode = 200;
      res.setHeader('Content-Type', contentTypeFor(fullPath));
      res.end(data);
    } catch {
      res.statusCode = 404;
      res.end('Not found');
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('admin statistics screen renders trend chart, heatmap and table search', async ({ page }) => {
  const staticServer = await startStaticServer();
  try {
    const { baseUrl } = staticServer;

    await page.addInitScript((origin) => {
      window.SHADOWDOG_CONFIG = window.SHADOWDOG_CONFIG || {};
      window.SHADOWDOG_CONFIG.apiBase = origin;
      window.SHADOWDOG_CONFIG.adminUsername = 'harel';
      window.API_BASE = origin;
      localStorage.setItem('shadowdog_audio_muted', '1');
    }, baseUrl);

  const usersPayload = [
    {
      id: 1,
      username: 'harel',
      created_at: '2026-01-01T10:00:00.000Z',
      total_play_time_ms: 360000,
      games_played: 6,
      games_won: 3,
      best_score: 140,
      last_played_at: '2026-02-14T10:30:00.000Z',
    },
    {
      id: 2,
      username: 'alex',
      created_at: '2026-01-02T11:00:00.000Z',
      total_play_time_ms: 120000,
      games_played: 3,
      games_won: 1,
      best_score: 90,
      last_played_at: '2026-02-13T09:30:00.000Z',
    },
  ];

    await page.route('**/auth/me', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ user: { id: 1, username: 'harel' } }),
      });
    });

    await page.route('**/admin/dashboard?limit=200', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          overview: {
            total_users: 2,
            total_games: 9,
            total_play_time_ms: 480000,
            total_wins: 4,
          },
          users: usersPayload,
        }),
      });
    });

    await page.route('**/admin/traffic?**', async (route) => {
      const rows = Array.from({ length: 7 }, (_, i) => ({
        day: `2026-02-${String(8 + i).padStart(2, '0')}`,
        sessions: i + 1,
        users: i % 3 === 0 ? 2 : 1,
      }));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(rows),
      });
    });

    await page.route('**/admin/active-hours?**', async (route) => {
      const rows = Array.from({ length: 24 }, (_, hour) => ({
        hour,
        sessions: hour % 4 === 0 ? 3 : 0,
        users: hour % 4 === 0 ? 2 : 0,
      }));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(rows),
      });
    });

    await page.goto(`${baseUrl}/game.html`, { waitUntil: 'domcontentloaded' });

    await expect(page.locator('#adminPanelButton')).toBeVisible();
    await page.click('#adminPanelButton');
    await expect(page.locator('#adminScreen')).toBeVisible();

    await expect(page.locator('#adminWeeklyTrend svg')).toBeVisible();
    await expect(page.locator('#adminWeeklyTrend .adminTrendPath')).toHaveCount(1);
    await expect(page.locator('#adminActiveHours .adminHeatmapCell')).toHaveCount(24);

    await expect(page.locator('#adminUsersBody tr')).toHaveCount(2);
    await page.fill('#adminUserSearch', 'alex');
    await expect(page.locator('#adminUsersBody tr')).toHaveCount(1);
    await expect(page.locator('#adminUsersBody tr td').first()).toHaveText('alex');
  } finally {
    await staticServer.close();
  }
});

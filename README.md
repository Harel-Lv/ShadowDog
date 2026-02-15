# ShadowDog

## Authentication

The game now supports account signup/login with `username + password` (no email).

- `POST /auth/signup` with `{ username, password }`
- `POST /auth/login` with `{ username, password }`
- `POST /auth/logout` clears the session cookie
- `GET /auth/me` returns the logged-in user (cookie-based session)

`POST /scores` requires authentication and saves score for the logged-in user only.

## Admin score reset

To allow score reset (`DELETE /scores`), set an admin token in the server environment:

`ADMIN_RESET_TOKEN=your-secret-token`
`ADMIN_USERNAME=your-admin-username`

Only an authenticated session of `ADMIN_USERNAME` can reset scores.
When clicking `Reset Scores` in the client, enter the admin token when prompted.
Default admin username is `harel` if `ADMIN_USERNAME` is not set.

## CORS configuration

Set allowed browser origins with:

`CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500`

If not set, the server allows common local dev origins (`localhost/127.0.0.1` on ports `5500` and `3000`).

## Admin UI visibility

Admin actions are shown only when a logged-in username matches `ADMIN_USERNAME` on the server.

Also make sure the client API base and server port match (for example, `window.API_BASE = 'http://127.0.0.1:3002'` with `PORT=3002`).

## Automated tests

Run server tests with:

`cd server && npm test`

Run UI E2E browser tests (Statistics screen: chart + heatmap + search) with:

`cd server && npx playwright install chromium && npm run test:e2e:ui`

Run all tests together:

`cd server && npm run test:all`

## Score rate limit

`POST /scores` is rate-limited per IP.

Optional server env vars:

- `SCORE_RATE_LIMIT_MAX` (default: `30`)
- `SCORE_RATE_LIMIT_WINDOW_MS` (default: `60000`)

`DELETE /scores` (admin reset) is also rate-limited per IP.

- `ADMIN_RATE_LIMIT_MAX` (default: `5`)
- `ADMIN_RATE_LIMIT_WINDOW_MS` (default: `60000`)
- `ADMIN_READ_RATE_LIMIT_MAX` (default: `60`) for admin read endpoints (`/admin/dashboard`, `/admin/overview`, `/admin/users`, `/admin/traffic`, `/admin/active-hours`)
- `ADMIN_READ_RATE_LIMIT_WINDOW_MS` (default: `60000`)

## Auth limits and session TTL

Optional server env vars:

- `AUTH_RATE_LIMIT_MAX` (default: `10`)
- `AUTH_RATE_LIMIT_WINDOW_MS` (default: `60000`)
- `ANALYTICS_RATE_LIMIT_MAX` (default: `120`)
- `ANALYTICS_RATE_LIMIT_WINDOW_MS` (default: `60000`)
- `RATE_LIMITER_MAX_ENTRIES` (default: `10000`)
- `SESSION_COOKIE_NAME` (default: `shadowdog_session`)
- `SESSION_COOKIE_SAMESITE` (default: `lax` in dev, recommended `none` when client/API are on different sites)
- `RATE_LIMIT_STORE` (default: `memory`, recommended: `database` on shared deployments)
- `SESSION_TTL_MS` (default: `604800000` = 7 days)
- `TRUST_PROXY` (default: `false`, recommended `1` behind a single reverse proxy hop)
- `AUTO_MIGRATE_ON_START` (default: `false`; enable only if you want schema bootstrap on startup)
- `STATS_CACHE_ENABLED` (default: `true`; in-memory cache for admin statistics endpoints)
- `STATS_CACHE_TTL_MS` (default: `15000`)
- `STATS_CACHE_MAX_ENTRIES` (default: `200`)

Note: browser auth now uses an `HttpOnly` session cookie by default (not accessible from JavaScript).

## Deploy on Render

This repo includes `render.yaml` for:

- `shadowdog-api` (Node web service)
- `shadowdog-db` (PostgreSQL)
- `shadowdog-client` (static site)

Steps:

1. Push repo to GitHub.
2. In Render, create a new **Blueprint** and select this repo.
3. After services are created, set these env vars on `shadowdog-api`:
   - `ADMIN_USERNAME`
   - `ADMIN_RESET_TOKEN`
   - `CORS_ORIGINS` (your client URL, e.g. `https://shadowdog-client.onrender.com`)
   - `TRUST_PROXY=1`
4. Run `server/db/schema.sql` on the new Render database.
5. Update client API URL in `client/game.html`:
   - set `window.SHADOWDOG_CONFIG.apiBase` to your API URL (e.g. `https://shadowdog-api.onrender.com`)
6. Redeploy.

# ShadowDog

## Authentication

The game now supports account signup/login with `username + password` (no email).

- `POST /auth/signup` with `{ username, password }`
- `POST /auth/login` with `{ username, password }`
- `POST /auth/logout` with `Authorization: Bearer <token>`

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

## Admin UI toggle

To show the `Reset Scores` button in the client, set:

`window.IS_ADMIN = true`

`'true'`, `1`, and `'1'` are also accepted.

Also make sure the client API base and server port match (for example, `window.API_BASE = 'http://127.0.0.1:3002'` with `PORT=3002`).

## Automated tests

Run server tests with:

`cd server && npm test`

## Score rate limit

`POST /scores` is rate-limited per IP.

Optional server env vars:

- `SCORE_RATE_LIMIT_MAX` (default: `30`)
- `SCORE_RATE_LIMIT_WINDOW_MS` (default: `60000`)

`DELETE /scores` (admin reset) is also rate-limited per IP.

- `ADMIN_RATE_LIMIT_MAX` (default: `5`)
- `ADMIN_RATE_LIMIT_WINDOW_MS` (default: `60000`)

## Auth limits and session TTL

Optional server env vars:

- `AUTH_RATE_LIMIT_MAX` (default: `10`)
- `AUTH_RATE_LIMIT_WINDOW_MS` (default: `60000`)
- `SESSION_TTL_MS` (default: `2592000000` = 30 days)
- `TRUST_PROXY` (default: `false`, set to `true` behind a reverse proxy)
- `AUTO_MIGRATE_ON_START` (default: `false`; enable only if you want schema bootstrap on startup)

Note: auth token is stored in `sessionStorage` (not `localStorage`) so browser restarts log users out by default.

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
   - `TRUST_PROXY=true`
4. Run `server/db/schema.sql` on the new Render database.
5. Update client API URL in `client/game.html`:
   - set `window.SHADOWDOG_CONFIG.apiBase` to your API URL (e.g. `https://shadowdog-api.onrender.com`)
6. Redeploy.

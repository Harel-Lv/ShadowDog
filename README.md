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

When clicking `Reset Scores` in the client, enter that token when prompted.

## CORS configuration

Set allowed browser origins with:

`CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500`

If not set, the server allows common local dev origins (`localhost/127.0.0.1` on ports `5500` and `3000`).

## Admin UI toggle

To show the `Reset Scores` button in the client, set:

`window.IS_ADMIN = true`

`'true'`, `1`, and `'1'` are also accepted.

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

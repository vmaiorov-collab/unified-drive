# Unified Drive

Несколько личных Google-аккаунтов как один диск. Подробный план: `~/.claude/plans/wobbly-purring-aurora.md`.

- `worker/` — Cloudflare Worker (API, OAuth, cron) + D1 (`migrations/`)
- `web/` — статический UI для GitHub Pages

## Первый запуск

1. Google Cloud Console: создать проект, включить Drive API, OAuth consent screen (External, затем Publish app — иначе токены живут 7 дней), создать OAuth client (Web), redirect URI = `https://<worker>.workers.dev/oauth/callback`.
2. `cd worker && npx wrangler d1 create unified-drive`, вписать `database_id` в `wrangler.toml`, затем `npx wrangler d1 migrations apply unified-drive --remote`.
3. Секреты: `npx wrangler secret put GOOGLE_CLIENT_ID | GOOGLE_CLIENT_SECRET | REDIRECT_URI | TOKEN_KEY | ADMIN_TOKEN | WEB_ORIGIN`.
   `TOKEN_KEY` = `openssl rand -base64 32`.
4. `npm run deploy`, подставить URL воркера в `web/index.html` (`API`), включить GitHub Pages для `web/`.

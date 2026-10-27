# Aegis Dashboard

Security dashboard for the [Aegis gateway](../README.md): threats detected, requests by decision, block reasons, top detector rules, the audit log, and per-tenant token budgets. Sign-in is required, with `admin`, `analyst` and `viewer` roles (see the main README).

```bash
npm install
cp .env.example .env.local   # AEGIS_URL, AEGIS_ADMIN_TOKEN (matches the gateway ADMIN_TOKEN), SESSION_SECRET
npm run dev                  # http://localhost:3000
```

Create a login from the gateway folder: `npm run user -- create you@example.com admin`.

All data is fetched in Server Components after a server-side role check, so the admin token never reaches the browser.

`npm run build && npm start` runs the production standalone server; `Dockerfile` packages the same output.

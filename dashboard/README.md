# Aegis Dashboard

Security dashboard for the [Aegis gateway](../README.md): threats detected, requests by decision, block reasons, top detector rules, the audit log, and per-tenant token budgets.

```bash
npm install
cp .env.example .env.local   # AEGIS_URL and AEGIS_ADMIN_TOKEN (must match the gateway's ADMIN_TOKEN)
npm run dev                  # http://localhost:3000
```

All data is fetched in Server Components, so the admin token never reaches the browser. If the gateway is unreachable, each page shows an inline error explaining what to check.

`npm run build && npm start` runs the production standalone server; `Dockerfile` packages the same output.

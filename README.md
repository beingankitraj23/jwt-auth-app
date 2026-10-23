# JWT Auth (Express + bcrypt + JWT) — Vercel ready

## Run locally (no setup needed)
```
npm install
npm run dev        # http://localhost:3000
```
No `.env` required: a temporary JWT secret is generated and users are kept in memory
(they disappear on restart). To use your own values, copy `.env.example` to `.env`.

## Endpoints
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | – | `{name, email, password}` → creates user, sets cookie |
| POST | `/api/auth/login` | – | `{email, password}` → sets cookie, returns token |
| POST | `/api/auth/logout` | – | clears cookie |
| GET | `/api/auth/me` | JWT | current user |
| GET | `/api/protected/dashboard` | JWT | sample protected data |

The JWT is sent in an HTTP-only cookie and also accepted as `Authorization: Bearer <token>`.

## Deploy on Vercel
1. Create a free Postgres database (Neon, Supabase or Vercel Postgres) and copy the connection string.
2. Push this folder to GitHub (`node_modules` and `.env` are gitignored) and import it in Vercel.
3. Project Settings → Environment Variables, add:
   - `JWT_SECRET` – 32+ random chars (generate with the command in `.env.example`)
   - `DATABASE_URL` – your Postgres connection string
4. Redeploy (env changes only apply to new deployments). The `users` table is created automatically.

# Deployment Guide: OT Asset Discovery & Inventory Scanner

## Architecture

```
┌─────────────────┐         ┌──────────────────────┐         ┌────────────┐
│  Vercel          │  REST   │  Railway / Render     │         │ PostgreSQL │
│  (React Frontend)│────────▶│  (FastAPI Backend)    │────────▶│ (Database) │
│                  │◀────────│                       │◀────────│            │
│                  │   WS    │                       │         │            │
└─────────────────┘         └──────────────────────┘         └────────────┘
```

## Step 1: Deploy Backend (Railway)

### Option A: Railway (Recommended)

1. Push the project to GitHub (if not already):
   ```bash
   cd ot-asset-discovery
   git add .
   git commit -m "Add deployment configuration"
   git push origin main
   ```

2. Go to [railway.app](https://railway.app) and create a new project

3. Add a **PostgreSQL** database service:
   - Click "New" → "Database" → "PostgreSQL"
   - Railway auto-provisions the database

4. Add a **Web Service** from your GitHub repo:
   - Click "New" → "GitHub Repo" → select `ot-asset-discovery`
   - Railway detects the `Dockerfile` and `railway.toml` automatically

5. Set environment variables in the Railway dashboard:
   ```
   DATABASE_URL=<auto-linked from PostgreSQL service>
   JWT_SECRET_KEY=<generate a secure random string>
   CORS_ORIGINS=https://your-frontend.vercel.app
   ```

6. After deploy, note your backend URL (e.g., `https://ot-asset-discovery-production.up.railway.app`)

7. Run database migrations:
   ```bash
   railway run alembic upgrade head
   ```

### Option B: Render

1. Push to GitHub

2. Go to [render.com](https://render.com) → "New" → "Blueprint"

3. Connect your repo — Render reads `render.yaml` and creates:
   - Web service (FastAPI backend)
   - PostgreSQL database (free tier)

4. Set the `CORS_ORIGINS` env var to your Vercel frontend URL

5. Note your backend URL (e.g., `https://ot-asset-discovery-api.onrender.com`)

## Step 2: Deploy Frontend (Vercel)

1. Go to [vercel.com](https://vercel.com) → "New Project"

2. Import your GitHub repo

3. Configure the project:
   - **Root Directory**: `frontend`
   - **Framework Preset**: Vite
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`

4. Set environment variables in Vercel dashboard:
   ```
   VITE_DEMO_MODE=false
   VITE_API_BASE_URL=https://your-backend-url.railway.app
   VITE_WS_BASE_URL=wss://your-backend-url.railway.app
   ```

5. Deploy!

## Step 3: Create Initial Admin User

After both services are running, create the first admin user by calling the backend directly:

```bash
# Using curl against your Railway backend
curl -X POST https://your-backend-url.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-secure-password", "role": "admin"}'
```

Or connect to the database and insert directly:

```sql
INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'admin', '<bcrypt-hash>', 'admin', NOW(), NOW());
```

## Environment Variables Reference

### Backend (Railway/Render)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string (asyncpg format) |
| `JWT_SECRET_KEY` | Yes | — | Secret key for JWT signing |
| `JWT_EXPIRATION_HOURS` | No | 8 | JWT token expiry in hours |
| `CORS_ORIGINS` | Yes | — | Comma-separated allowed origins |
| `APP_HOST` | No | 0.0.0.0 | Server bind host |
| `APP_PORT` | No | 8000 | Server bind port (Railway sets `$PORT`) |
| `CAPTURE_INTERFACE` | No | — | Network interface for packet capture |

### Frontend (Vercel)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_DEMO_MODE` | No | true | Set to `false` for production |
| `VITE_API_BASE_URL` | Yes* | — | Backend URL (e.g., `https://api.example.com`) |
| `VITE_WS_BASE_URL` | Yes* | — | WebSocket URL (e.g., `wss://api.example.com`) |

*Required when `VITE_DEMO_MODE=false`

## Notes

- **Packet capture limitation**: Scapy requires raw socket access, which isn't available on most PaaS platforms. On Railway/Render, the scan simulation and API work fine, but real passive sniffing requires a VPS/EC2 with `CAP_NET_RAW` capability.
- **WebSocket support**: Both Railway and Render support WebSocket connections natively.
- **Database migrations**: Run `alembic upgrade head` after first deploy to create tables.
- **Demo mode**: Set `VITE_DEMO_MODE=true` on Vercel if you want to showcase the UI without a running backend.

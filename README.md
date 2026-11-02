# RAJAWALI

### Reconnaissance Awareness & Judgment for Active Warfare Intelligence

RAJAWALI is a defensive deception platform that detects reconnaissance, profiles
threat behavior, and provides an isolated honeypot environment for authorized
security monitoring.

## Capabilities

- Early reconnaissance and port-scan detection
- SSH and HTTP deception services
- Behavioral profiling and MITRE ATT&CK mapping
- Threat scoring, alerting, and attacker reports
- Real-time Next.js operations dashboard
- PostgreSQL persistence and Redis event signaling

## Stack

| Component | Technology |
| --- | --- |
| Backend API | FastAPI, SQLAlchemy async, PostgreSQL |
| Honeypot | Go |
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Intelligence | scikit-learn, AbuseIPDB, MITRE ATT&CK |
| Deployment | Docker Compose, Nginx |

## Quick start

Requirements: Docker Desktop, Go 1.22+, Python 3.11+, and Node.js 18+.

Create a production environment file before starting the stack:

```env
POSTGRES_DB=rajawali
POSTGRES_USER=rajawali
POSTGRES_PASSWORD=<strong-database-password>
REDIS_PASSWORD=<strong-redis-password>
SECRET_KEY=<random-value-at-least-32-characters>
HONEYPOT_TOKEN=<random-internal-token>
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<bcrypt-hash>
ENV=production
NEXT_PUBLIC_API_URL=
```

## TLS with Let's Encrypt

You need a domain name pointing to the server. Replace `example.com` with
your real domain and make sure ports 80 and 443 are reachable.

Install Certbot on the host, stop any service currently using ports 80/443,
and request the certificate:

```bash
sudo apt-get update
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d example.com
sudo mkdir -p infra/nginx/certs
sudo cp /etc/letsencrypt/live/example.com/fullchain.pem infra/nginx/certs/
sudo cp /etc/letsencrypt/live/example.com/privkey.pem infra/nginx/certs/
sudo chmod 600 infra/nginx/certs/privkey.pem
```

Set `server_name example.com;` in `infra/nginx/nginx.conf`, then run:

```bash
docker compose up -d --build
```

Renew and deploy the certificate monthly:

```bash
sudo certbot renew --deploy-hook "cp /etc/letsencrypt/live/example.com/fullchain.pem /path/to/RAJAWALI/infra/nginx/certs/fullchain.pem && cp /etc/letsencrypt/live/example.com/privkey.pem /path/to/RAJAWALI/infra/nginx/certs/privkey.pem && docker compose -f /path/to/RAJAWALI/docker-compose.yml exec -T nginx nginx -s reload"
```

The dashboard is available at `https://example.com/`. The API is intentionally
reachable through Nginx only. Sign in through the dashboard using
`ADMIN_USERNAME` and the password used to create `ADMIN_PASSWORD_HASH`.

```http
Authorization: Bearer <JWT>
```

The honeypot exposes SSH on port `2222` and HTTP on port `8080`. These services
are intentionally exposed for authorized deception testing. Never deploy them
on infrastructure you do not own or have explicit permission to monitor.

## Development

Run the backend before opening the dashboard. The development frontend
automatically proxies `/api/*` to `http://127.0.0.1:8000`; the Docker Compose
deployment uses the internal `backend` hostname instead.

Start the development database services first. The override publishes
PostgreSQL and Redis only on loopback, so they are available to locally run
processes without being exposed to the network:

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres redis
```

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Honeypot
cd honeypot
go run ./cmd
```

Validation commands:

```bash
cd backend && pytest
cd frontend && npm run lint && npm run build
cd honeypot && go test ./... && go vet ./...
```

## Security notes

- Production startup fails when required secrets or the admin password hash are missing.
- Analyst access uses short-lived JWTs in an HttpOnly, Secure, SameSite cookie.
- Honeypot ingestion uses a separate internal token and is not exposed to analysts.
- API documentation is disabled in production.
- Nginx redirects HTTP to HTTPS and applies security headers and rate limits.
- Captured passwords are discarded and never returned by event APIs.
- PostgreSQL, Redis, the backend, and the frontend are private Compose services.
- Use unique secrets, rotate credentials, and restrict host firewall access.

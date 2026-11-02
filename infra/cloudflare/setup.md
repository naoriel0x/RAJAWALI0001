# Cloudflare deployment checklist

Cloudflare should sit in front of the Nginx service. Do not put database,
Redis, or honeypot ports behind the public proxy.

## DNS

1. Add an `A` or `CNAME` record for the dashboard hostname.
2. Set the record to **Proxied** (orange cloud).
3. Keep PostgreSQL (`5432`), Redis (`6379`), SSH honeypot (`2222`), and the
   development HTTP honeypot port (`8080`) unproxied or firewall-restricted.

## TLS

1. Set Cloudflare SSL/TLS mode to **Full (strict)**.
2. Create an Origin Certificate in Cloudflare.
3. Store the certificate and private key outside source control, for example:
   `infra/nginx/certs/fullchain.pem` and `infra/nginx/certs/privkey.pem`.
4. Add an HTTPS server block using the directives in `infra/nginx/ssl.conf`.
5. Redirect port 80 to HTTPS after verifying the certificate.

## Firewall and origin access

- Allow ports 80/443 only from the public edge or required administrative
  networks.
- Restrict the origin firewall so the dashboard is not reachable by bypassing
  Cloudflare.
- Configure Cloudflare rate limiting and WAF rules for `/api/` and login-like
  honeypot paths.
- Never commit `.env`, API keys, origin certificates, or private keys.
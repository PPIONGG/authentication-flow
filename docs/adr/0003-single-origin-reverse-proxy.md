# Single origin via a reverse proxy

A Caddy reverse proxy sits in front of everything and serves the React SPA at `/` while proxying
the API under `/api`, so the browser and the API share **one origin**. We rejected the common
alternative of deploying the SPA and API on separate origins.

**Why:** a single origin makes the session cookie first-party, which keeps it simple and lets us
use a `__Host-` prefix; the CSRF model is cleaner; and it mirrors a realistic production topology.
Separate origins would force CORS with credentials plus `SameSite=None` cookies — more moving
parts and a larger attack surface, for no benefit here.

**Trade-off:** we run a reverse proxy container even in development (one extra service in the
compose file). Accepted, because the dev/prod parity it buys is worth more than the one container.

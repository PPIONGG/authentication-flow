# Build authentication in-house

We considered a self-hosted identity provider (Keycloak) and managed SaaS (Clerk / Auth0 /
Supabase Auth), but chose to build authentication ourselves — an Express API owning the user
store, password hashing, and sessions, backed by our own Postgres and Redis. The project's goal
is to understand and own every part of the auth flow and to run fully self-contained in Docker
with no external SaaS dependency.

**Trade-off:** we take on full responsibility for auth security ourselves. Mitigated by the
baseline hardening recorded in `ROADMAP.md` §10. Revisit if the project ever needs SSO
federation, an admin console, or enterprise SAML out of the box — that is when Keycloak or a
managed provider starts to pay for itself.

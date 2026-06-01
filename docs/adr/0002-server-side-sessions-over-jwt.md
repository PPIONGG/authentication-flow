# Server-side opaque sessions, not JWT

Auth state is a **server-side Session**: an opaque, random session ID stored in a
`__Host-`-prefixed `httpOnly` + `Secure` + `SameSite` cookie, with the session record held in
Redis. We deliberately rejected JWT access/refresh tokens for the web client.

**Why:** instant revocation (sign-out-everywhere, kill a session on compromise) is a first-class
requirement; an opaque ID in an `httpOnly` cookie cannot be read or exfiltrated by JavaScript
even under XSS; and "a login is a row in Redis, sign-out deletes it" is a far simpler mental
model than refresh-token rotation.

**Trade-off:** the system is stateful and depends on Redis, and this design is not ideal for
stateless multi-service backends or native mobile clients. If those needs appear, revisit JWT
(access in memory + refresh-token rotation) — see `ROADMAP.md` §3. This ADR exists so the next
reader who asks "why didn't they just use JWT?" finds the answer.

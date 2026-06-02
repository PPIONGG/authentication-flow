# Authentication Flow

A self-hosted, full-stack reference implementation of web authentication: a Vite + React
single-page app and a Node/TypeScript API that own all auth logic and run entirely in Docker.

## Language

**User**:
A person who holds an identity in the system and can sign in. The single canonical word for
the human behind a login.
_Avoid_: Account, Member, Customer

**Credential**:
A secret a User presents to prove who they are. For now an email + password pair — the
password itself is never stored, only its hash.
_Avoid_: Login, password (when you mean the whole pair)

**Session**:
A period during which a User is recognized as signed in. Represented by an opaque ID held in
an `httpOnly` cookie on the browser and a matching record in the server-side session store
(Redis). Ending a Session = signing out.
_Avoid_: Token, JWT, auth cookie (when you mean the whole concept)

**Sign in / Sign out**:
The acts of starting / ending a Session. Use these two verbs consistently in UI copy and code.
_Avoid_: Log in / log out, authenticate (as a UI word)

**Reset password** vs **Change password**:
Two distinct flows that are easy to confuse.

- _Reset password_ — recovering access while signed **out** (the User forgot it), proven by a
  single-use token sent to their email.
- _Change password_ — updating the password while signed **in**, proven by entering the current
  password.
_Avoid_: using "reset" and "change" interchangeably.

**Verification token**:
A single-use, time-limited secret emailed to a User to prove they control an email address
(used by email verification and, with the same shape, by password reset). Stored hashed, never
reusable once consumed.
_Avoid_: code, link, OTP (reserve OTP for 2FA later)

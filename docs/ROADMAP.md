# Auth — Decisions & Future Expansion

> สิ่งที่ **เลือกแล้วตอนนี้ (✅)** vs **ของที่ยังไม่ได้ลอง / ค่อยกลับมาเติมทีหลัง (🔜)** แยกตามหัวข้อ
> เป้าหมาย: เข้าใจพื้นฐานให้แน่นก่อน แล้วค่อยขยายทีละชิ้นโดยไม่ต้องรื้อของเดิม
>
> 🛠️ **แผนการสร้างจริง (TDD ทีละ step):** ดู [`superpowers/plans/`](./superpowers/plans/README.md)
> — 6 แผนเรียงลำดับ build + [`CONTRACTS.md`](./superpowers/plans/CONTRACTS.md) (สัญญา interface ร่วม)

---

## 1. ความเป็นเจ้าของระบบ (Ownership)

- ✅ **สร้าง auth เองทั้งหมด** — own backend + own database, รันใน Docker แบบ self-contained
- 🔜 ยังไม่ได้ลอง:
  - **Keycloak** (self-host identity provider, OIDC/OAuth2 มาตรฐาน) — เหมาะเมื่อต้องการ admin UI, federation, SSO สำเร็จรูป
  - **Managed SaaS** (Clerk / Auth0 / Supabase Auth) — เหมาะเมื่ออยากเร็วและไม่อยากดูแล security เอง

## 2. รูปทรงสถาปัตยกรรม (Architecture)

- ✅ **Vite React SPA + Node/TypeScript API แยก service**, มี **reverse proxy** หน้าสุดให้ทั้งคู่อยู่ origin เดียวกัน
- ✅ Backend framework: **Express** + **Zod** (validate input ทุก request)
- 🔜 ยังไม่ได้ลอง:
  - Backend framework อื่น: **Fastify** (เร็วกว่า), **NestJS** (โครงสร้างชัด เหมาะทีม)
  - **Next.js full-stack** (แอปเดียว, server components/actions)
  - **Backend ภาษาอื่น** (Go / Python / Rust) เบื้องหลัง React เดิม
  - **BFF (Backend-for-Frontend)** pattern แยกชัดเจน

## 3. กลยุทธ์ Session / Token

- ✅ **Opaque session ID + httpOnly cookie + Redis session store** (stateful, เพิกถอนได้ทันที, กัน XSS ขโมย session)
- 🔜 ยังไม่ได้ลอง:
  - **JWT access (in-memory) + refresh token rotation** (stateless, เหมาะ mobile/microservices)
  - **Sliding vs absolute session expiry** tuning, "remember me" ระยะยาว
  - **Token binding / device-bound sessions**

## 4. วิธีล็อกอิน (Login methods)

- ✅ **Email + Password** (พื้นฐาน + ได้เรียน password hashing ที่ถูกต้อง)
- 🔜 ยังไม่ได้ลอง:
  - **Social login** — Google / GitHub OAuth2 (OIDC flow)
  - **Magic link** (passwordless ทางอีเมล)
  - **Passkey / WebAuthn** (ลายนิ้วมือ/Face ID, กัน phishing)
  - **SSO / SAML** สำหรับลูกค้าองค์กร

## 5. ฟีเจอร์บัญชี (Account lifecycle)

- ✅ **ครบวงจรแบบ production** (พึ่งระบบส่งอีเมล → ใช้ **Mailpit** ใน dev):
  - สมัครสมาชิก (register)
  - **ยืนยันอีเมล** ตอนสมัคร (verification token หมดอายุ ใช้ครั้งเดียว)
  - ล็อกอิน / ล็อกเอาท์
  - **ลืม/รีเซ็ตรหัสผ่าน** (reset token ทางอีเมล)
  - **เปลี่ยนรหัสผ่าน** (ตอนล็อกอินอยู่ ต้องยืนยันรหัสเก่า)
  - **เปลี่ยนอีเมล** (ต้องยืนยันอีเมลใหม่ก่อนมีผล)
  - **logout ทุกอุปกรณ์** (ลบทุก session ใน Redis)
- 🔜 ยังไม่ได้ลอง:
  - **2FA / TOTP** (Google Authenticator) + recovery codes
  - **ดูรายการ session/อุปกรณ์** ที่ล็อกอินอยู่ แล้วเตะออกทีละอัน
  - **แจ้งเตือนทางอีเมล** เมื่อมีการล็อกอินจากอุปกรณ์ใหม่

## 6. การอนุญาต (Authorization / roles)

- ✅ **RBAC ง่ายๆ: role = `user` | `admin`** บน User, มี middleware กันเส้นทาง/หน้าเฉพาะ admin
- 🔜 ยังไม่ได้ลอง:
  - **Permissions ละเอียด** (เช่น `post:delete`, `user:ban`) แล้ว map role → permissions
  - **Resource-based / ownership checks** (เจ้าของข้อมูลเท่านั้นที่แก้ได้)
  - **Organizations / teams / multi-tenancy** (ผู้ใช้อยู่หลายองค์กร, role ต่อองค์กร)
  - **Policy engine** (เช่น CASL, OPA) เมื่อกฎซับซ้อนขึ้น

## 7. ชั้นข้อมูล (Data layer: DB / ORM / hashing)

- ✅ **PostgreSQL** (DB หลัก) + **Prisma** (schema + migrations, type-safe) + **argon2id** (hash รหัสผ่าน) + **Redis** (session store)
- 🔜 ยังไม่ได้ลอง:
  - ORM อื่น: **Drizzle** (เบา ใกล้ SQL) หรือ **raw SQL**
  - hashing อื่น: **bcrypt** (เก่ากว่าแต่ยังโอเค), เพิ่ม **pepper** เก็บแยกจาก DB
  - **audit log / soft delete** columns, read replica, DB-level Row-Level Security

## 8. Frontend (React) — route protection, auth state, forms

- ✅ **Vite + React + TypeScript**, **React Router** (protected routes), **TanStack Query** (สถานะ session จาก server), **React Hook Form + Zod** (ฟอร์ม + validate)
- 🔜 ยังไม่ได้ลอง:
  - SSR/SEO ด้วย **Next.js**
  - global state lib (**Zustand/Redux**) ถ้าจำเป็น, **shadcn/ui** component library
  - i18n หลายภาษา, accessibility (a11y) pass, optimistic UI

## 9. Docker / Infra

- ✅ **Dev docker compose** 6 services: `caddy` (reverse proxy, single origin), `web` (Vite), `api` (Express), `db` (Postgres + volume), `redis`, `mailpit`
- ✅ `docker compose up` ครั้งเดียว, hot reload, `.env` เก็บ secrets, Prisma migrate ตอน api boot, healthcheck + depends_on
- ✅ เอกสารทางไป prod (ยังไม่ build จริง)
- 🔜 ยังไม่ได้ลอง:
  - **Prod compose**: build React เป็น static ให้ Caddy เสิร์ฟ, real SMTP, auto-HTTPS, docker secrets
  - **CI/CD** (test + build image), container registry
  - **Observability**: structured logs, metrics, tracing
  - **Backups** ของ Postgres volume, scale `api` หลาย instance (Redis session ทำให้ scale ได้เลย)

## 10. ความปลอดภัยเพิ่มเติม (Security hardening)

- ✅ **Baseline (ใส่ทุกข้อ)**: argon2id + นโยบายรหัส, rate-limit + lockout (ต่อ IP/บัญชี), กัน account enumeration, regenerate session ตอน login, cookie `__Host-`+httpOnly+Secure+SameSite, CSRF double-submit token, CORS ล็อก origin + Helmet (CSP/HSTS), token hygiene (hash/single-use/expiry/timing-safe), Zod ทุก input, HTTPS (Caddy), secrets ใน `.env`
- ✅ **Extra**: Audit log ของ auth events (login/logout/fail/เปลี่ยนรหัส)
- 🔜 ยังไม่ได้ลอง:
  - **เช็ครหัสที่เคยหลุด** (HaveIBeenPwned k-anonymity) — ต้องต่อเน็ตออก
  - **CAPTCHA / bot protection** (hCaptcha/Turnstile) — ต้อง service + key ภายนอก
  - **แจ้งอีเมลเมื่อ login จากอุปกรณ์ใหม่**
  - **2FA/TOTP** (ดู §5 ด้วย), security monitoring/alerting, การทำ pentest

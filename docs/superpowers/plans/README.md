# Implementation Plans — authentication-flow

แผนการสร้างทั้งหมด เรียงตามลำดับที่ควร build แต่ละแผน **build แล้วรัน/เทสได้จบในตัว** ก่อนไปแผนถัดไป

> 📐 **อ่าน [`CONTRACTS.md`](./CONTRACTS.md) ก่อนเสมอ** — เป็น "สัญญา" ของ interface ที่ใช้ร่วมกันข้ามแผน
> (ชื่อ export, signature, path convention `/api/...`, คำศัพท์ audit event). ถ้าโค้ดในแผนขัดกับ
> CONTRACTS ให้ยึด CONTRACTS

## ลำดับการ build

| # | แผน | สร้างอะไร | รันได้แค่ไหน | ต้องมีก่อน |
| --- | --- | --- | --- | --- |
| 00 | [scaffold & docker](./2026-06-01-00-scaffold-and-docker.md) | monorepo + 6 docker services + Prisma schema เต็ม + reverse proxy | `docker compose up` ขึ้นครบ, `https://localhost/api/health` ตอบ ok | — |
| 01 | [core auth (sessions)](./2026-06-01-01-core-auth-sessions.md) | register/login/logout/me + Redis session + CSRF + rate-limit + หน้า React | ล็อกอินจริง end-to-end ผ่านเบราว์เซอร์ | 00 |
| 02 | [email verification & reset](./2026-06-01-02-email-verification-and-reset.md) | mailer (Mailpit) + token + ยืนยันอีเมล + ลืม/รีเซ็ตรหัส + gate login | ยืนยันอีเมล/รีเซ็ตรหัส (ดูเมลใน Mailpit) | 01 |
| 03 | [account management](./2026-06-01-03-account-management.md) | เปลี่ยนรหัส/อีเมล + logout-all | จัดการบัญชีตอนล็อกอินอยู่ | 01, 02 |
| 04 | [rbac, admin, audit](./2026-06-01-04-rbac-admin-audit.md) | requireRole + หน้า admin + audit log viewer | กันหน้า admin, ดู audit events | 01 (+03 สำหรับ event) |
| 05 | [security hardening](./2026-06-01-05-security-hardening.md) | regression tests (429/CSRF/enumeration/cookie/fixation) + `SECURITY.md` | พิสูจน์ว่า baseline ความปลอดภัยทำงานจริง | 01–04 |

## วิธีลงมือทำแต่ละแผน

ทุกแผนเขียนในรูปแบบ **writing-plans** (TDD ทีละ step เล็กๆ: เขียนเทสที่ fail → รันให้ fail → เขียนโค้ดให้ผ่าน → commit) มีโค้ดจริงครบทุก step ไม่มี placeholder ใช้กับ:

- **superpowers:subagent-driven-development** — แยก subagent ต่อ task + review ระหว่าง task (แนะนำ)
- **superpowers:executing-plans** — รันใน session เดียว เป็นช่วงๆ มี checkpoint

## ที่มา

แผนชุดนี้ถูกสร้างและตรวจด้วย multi-agent workflow: (1) research API ปัจจุบันของไลบรารีจาก docs,
(2) ร่าง 6 แผนขนาน, (3) audit หาความไม่สอดคล้องข้ามแผน → พบ 16 จุด, (4) repair ให้ตรง
`CONTRACTS.md`. เวอร์ชันไลบรารีที่อ้างอิงเป็นของช่วงกลางปี 2026 — ตรวจ `npm outdated` ก่อนเริ่มจริง

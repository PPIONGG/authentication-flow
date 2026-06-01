import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import { RegisterBody, LoginBody } from "./auth.schema.js";
import { createUser, verifyCredentials } from "./auth.service.js";
import { prisma } from "../../db/prisma.js";
import { writeAudit } from "../../lib/audit.js";
import { addUserSession, removeUserSession } from "../../lib/sessionStore.js";

export const authRouter = Router();

function badRequest(res: Response): void {
  res.status(400).json({ error: "invalid_input" });
}

authRouter.post(
  "/register",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = RegisterBody.safeParse(req.body);
      if (!parsed.success) return badRequest(res);
      const user = await createUser(parsed.data.email, parsed.data.password);
      await writeAudit({
        userId: user.id,
        event: "register",
        ip: req.ip,
        userAgent: req.get("user-agent"),
      });
      res.status(201).json({ ok: true });
    } catch (err) {
      next(err);
    }
  },
);

authRouter.post(
  "/login",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = LoginBody.safeParse(req.body);
      if (!parsed.success) return badRequest(res);

      let user;
      try {
        user = await verifyCredentials(parsed.data.email, parsed.data.password);
      } catch (err) {
        await writeAudit({
          event: "login_fail",
          ip: req.ip,
          userAgent: req.get("user-agent"),
        });
        throw err;
      }

      // Anti-fixation: regenerate the session id before storing identity.
      req.session.regenerate((regenErr) => {
        if (regenErr) return next(regenErr);
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.save(async (saveErr) => {
          if (saveErr) return next(saveErr);
          try {
            await addUserSession(user.id, req.session.id);
            await writeAudit({
              userId: user.id,
              event: "login_success",
              ip: req.ip,
              userAgent: req.get("user-agent"),
            });
            res.status(200).json({
              user: { id: user.id, email: user.email, role: user.role },
            });
          } catch (postErr) {
            next(postErr);
          }
        });
      });
    } catch (err) {
      next(err);
    }
  },
);

authRouter.post(
  "/logout",
  (req: Request, res: Response, next: NextFunction) => {
    const userId = req.session.userId;
    const sid = req.session.id;
    req.session.destroy(async (destroyErr) => {
      if (destroyErr) return next(destroyErr);
      try {
        if (userId) await removeUserSession(userId, sid);
        res.clearCookie("__Host-sid", { path: "/" });
        res.status(204).end();
      } catch (err) {
        next(err);
      }
    });
  },
);

authRouter.get(
  "/me",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.session.userId) {
        res.status(401).json({ error: "unauthenticated" });
        return;
      }
      const user = await prisma.user.findUnique({
        where: { id: req.session.userId },
      });
      if (!user) {
        res.status(401).json({ error: "unauthenticated" });
        return;
      }
      res
        .status(200)
        .json({ user: { id: user.id, email: user.email, role: user.role } });
    } catch (err) {
      next(err);
    }
  },
);

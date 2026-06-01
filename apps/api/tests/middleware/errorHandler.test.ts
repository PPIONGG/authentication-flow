import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { errorHandler } from "../../src/middleware/errorHandler.js";
import { csrfInvalidError } from "../../src/middleware/csrf.js";

describe("errorHandler", () => {
  it("returns 500 with a generic message for unexpected errors", async () => {
    const app = express();
    app.get("/boom", () => {
      throw new Error("secret internal detail");
    });
    app.use(errorHandler);
    const res = await request(app).get("/boom").expect(500);
    expect(res.body).toEqual({ error: "internal_error" });
    expect(JSON.stringify(res.body)).not.toContain("secret internal detail");
  });

  it("returns 403 for the csrf invalid-token error", async () => {
    const app = express();
    app.get("/csrf-boom", () => {
      throw csrfInvalidError;
    });
    app.use(errorHandler);
    const res = await request(app).get("/csrf-boom").expect(403);
    expect(res.body).toEqual({ error: "invalid_csrf_token" });
  });
});

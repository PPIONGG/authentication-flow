import { z } from "zod";

export const RegisterBody = z.object({
  email: z.email(),
  password: z.string().min(8).max(256),
});
export type RegisterBody = z.infer<typeof RegisterBody>;

export const LoginBody = z.object({
  email: z.email(),
  password: z.string().min(1).max(256),
});
export type LoginBody = z.infer<typeof LoginBody>;

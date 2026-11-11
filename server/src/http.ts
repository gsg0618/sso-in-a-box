import type { NextFunction, Request, RequestHandler, Response } from "express";
import { ZodError } from "zod";

/** An error whose message is safe to show to the caller. */
export class HttpError extends Error {
  status: number;
  code: string;
  extra: Record<string, unknown>;

  constructor(status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/** Express 4 does not catch rejected promises, so every async handler goes through this. */
export const ah =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>): RequestHandler =>
  (req, res, next) => {
    fn(req, res, next).catch(next);
  };

export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.code, message: err.message, ...err.extra });
  }
  if (err instanceof ZodError) {
    const first = err.issues[0];
    const where = first?.path.length ? first.path.join(".") + ": " : "";
    return res.status(400).json({ error: "invalid_input", message: where + (first?.message ?? "Invalid input") });
  }
  console.error(err);
  return res.status(500).json({ error: "internal_error", message: "Something went wrong." });
}

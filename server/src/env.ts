import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(1),
  APP_URL: z.string().url(),
  WEB_URL: z.string().url(),
  PORT: z.coerce.number().default(4000),
  SECRETS_KEY: z
    .string()
    .refine((v) => Buffer.from(v, "base64").length === 32, "SECRETS_KEY must be 32 bytes, base64 encoded"),
  MOCK_IDP: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),
});

const parsed = schema.parse(process.env);

if (parsed.MOCK_IDP && parsed.NODE_ENV === "production") {
  throw new Error("MOCK_IDP must not be enabled in production: it lets anyone sign in as anyone.");
}

export const env = {
  ...parsed,
  APP_URL: parsed.APP_URL.replace(/\/$/, ""),
  WEB_URL: parsed.WEB_URL.replace(/\/$/, ""),
  isProd: parsed.NODE_ENV === "production",
};

import { execFileSync } from "node:child_process";

/** Brings the test database schema up to date before any test runs. */
export default function setup() {
  const url = process.env.TEST_DATABASE_URL ?? "postgresql://sso:sso@localhost:5432/sso_test";
  execFileSync("npx", ["prisma", "migrate", "deploy"], {
    env: { ...process.env, DATABASE_URL: url },
    stdio: "pipe",
  });
}

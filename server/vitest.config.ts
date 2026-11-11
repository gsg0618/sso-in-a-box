import { defineConfig } from "vitest/config";

const TEST_PORT = 4517;

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    globalSetup: ["test/globalSetup.ts"],
    // All files share one Postgres database and one port, so run them one at a time.
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 30_000,
    env: {
      NODE_ENV: "test",
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? "postgresql://sso:sso@localhost:5432/sso_test",
      PORT: String(TEST_PORT),
      APP_URL: "http://localhost:" + TEST_PORT,
      WEB_URL: "http://localhost:5173",
      // Fixed throwaway key, only ever used against the test database.
      SECRETS_KEY: Buffer.alloc(32, 7).toString("base64"),
      MOCK_IDP: "true",
    },
  },
});

import {
  hashPassword,
  randomTempPassword,
  verifyPassword,
} from "../../src/lib/password.js";

describe("password", () => {
  it("verifies a correct password and rejects a wrong one", async () => {
    const hash = await hashPassword("Secret123!");
    await expect(verifyPassword("Secret123!", hash)).resolves.toBe(true);
    await expect(verifyPassword("secret123!", hash)).resolves.toBe(false);
  });

  it("uses a random salt per hash", async () => {
    const first = await hashPassword("same-password");
    const second = await hashPassword("same-password");
    expect(first).not.toBe(second);
    await expect(verifyPassword("same-password", first)).resolves.toBe(true);
    await expect(verifyPassword("same-password", second)).resolves.toBe(true);
  });

  it("rejects malformed stored hashes without throwing", async () => {
    await expect(verifyPassword("x", "not-a-hash")).resolves.toBe(false);
    await expect(verifyPassword("x", "")).resolves.toBe(false);
  });

  it("generates a non-empty temp password", () => {
    expect(randomTempPassword().length).toBeGreaterThanOrEqual(12);
  });
});

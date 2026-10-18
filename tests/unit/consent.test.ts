import { consentSchema, registerSchema } from "../../src/validators/auth.js";

describe("consent schemas", () => {
  it("register requires terms_accepted === true", () => {
    const base = {
      email: "ana@example.com",
      password: "Secret123!",
      name: "Ana",
    };
    expect(registerSchema.safeParse(base).success).toBe(false);
    expect(
      registerSchema.safeParse({ ...base, terms_accepted: false }).success
    ).toBe(false);
    expect(
      registerSchema.safeParse({ ...base, terms_accepted: true }).success
    ).toBe(true);
  });

  it("consent endpoint only accepts an explicit true", () => {
    expect(consentSchema.safeParse({ accepted: true }).success).toBe(true);
    expect(consentSchema.safeParse({ accepted: false }).success).toBe(false);
    expect(consentSchema.safeParse({}).success).toBe(false);
  });
});

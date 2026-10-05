import {
  hashRefreshToken,
  newRefreshToken,
  signAccessToken,
  verifyAccessToken,
} from "../../src/lib/tokens.js";
import { AppError } from "../../src/middleware/error-handler.js";

const SUBJECT = "11111111-2222-4333-8444-555555555555";

describe("tokens", () => {
  it("round-trips role and hotel scope", () => {
    const token = signAccessToken({
      sub: SUBJECT,
      email: "ana@example.com",
      role: "MANAGER",
      hotel_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    });
    const claims = verifyAccessToken(token);
    expect(claims).toMatchObject({
      sub: SUBJECT,
      role: "MANAGER",
      hotel_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      scope: "hotel",
    });
  });

  it("marks global roles as global scope", () => {
    const token = signAccessToken({ sub: SUBJECT, email: "ana@example.com", role: "GUEST", hotel_id: null });
    expect(verifyAccessToken(token).scope).toBe("global");
  });

  it("rejects tampered payloads", () => {
    const token = signAccessToken({ sub: SUBJECT, email: "ana@example.com", role: "GUEST", hotel_id: null });
    const [header, , signature] = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({ sub: SUBJECT, role: "SUPER_ADMIN", exp: 9999999999 })
    ).toString("base64url");
    expect(() => verifyAccessToken(`${header}.${forged}.${signature}`)).toThrow(
      AppError
    );
  });

  it("rejects malformed tokens", () => {
    expect(() => verifyAccessToken("abc")).toThrow(AppError);
    expect(() => verifyAccessToken("")).toThrow(AppError);
  });

  it("stamps issuer and audience on every token", () => {
    const token = signAccessToken({ sub: SUBJECT, email: "ana@example.com", role: "GUEST", hotel_id: null });
    expect(verifyAccessToken(token)).toMatchObject({
      iss: "hotelsync",
      aud: "hotelsync-api",
      email_verified: false,
    });
  });

  it("rejects tokens with a non-HS256 alg header", () => {
    const token = signAccessToken({ sub: SUBJECT, email: "ana@example.com", role: "GUEST", hotel_id: null });
    const [, payload, signature] = token.split(".");
    const noneHeader = Buffer.from(
      JSON.stringify({ alg: "none", typ: "JWT" })
    ).toString("base64url");
    expect(() => verifyAccessToken(`${noneHeader}.${payload}.${signature}`)).toThrow(
      AppError
    );
  });

  it("rejects tokens with wrong issuer or audience", () => {
    const token = signAccessToken({ sub: SUBJECT, email: "ana@example.com", role: "GUEST", hotel_id: null });
    const [header, , signature] = token.split(".");
    const forged = Buffer.from(
      JSON.stringify({
        sub: SUBJECT,
        email: "ana@example.com",
        role: "SUPER_ADMIN",
        iss: "attacker",
        aud: "hotelsync-api",
        exp: 9999999999,
      })
    ).toString("base64url");
    expect(() => verifyAccessToken(`${header}.${forged}.${signature}`)).toThrow(
      AppError
    );
  });

  it("hashes refresh tokens deterministically", () => {
    const token = newRefreshToken();
    expect(token).toHaveLength(64);
    expect(hashRefreshToken(token)).toBe(hashRefreshToken(token));
    expect(hashRefreshToken(token)).not.toContain(token);
  });
});

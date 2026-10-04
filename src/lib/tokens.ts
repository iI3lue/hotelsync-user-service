import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { AppError } from "../middleware/error-handler.js";

export interface AccessClaims {
  sub: string;
  email: string;
  role: string;
  hotel_id: string | null;
  scope: "global" | "hotel";
  iat: number;
  exp: number;
}

export const ACCESS_TTL_SECONDS = 8 * 60 * 60;
export const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * Secreto HS256 compartido. En produccion debe venir de un secret manager;
 * para el alcance academico se distribuye por variable de entorno.
 */
export function getSecret(): string {
  const secret = process.env.AUTH_JWT_SECRET;
  if (secret && secret.length >= 32) return secret;
  if (process.env.NODE_ENV === "test") {
    return "test-secret-for-unit-tests-only-32b!";
  }
  throw new Error("AUTH_JWT_SECRET must be set (min 32 chars)");
}

function base64urlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

export function signAccessToken(input: {
  sub: string;
  email: string;
  role: string;
  hotel_id: string | null;
}): string {
  const header = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64urlEncode(
    JSON.stringify({
      sub: input.sub,
      email: input.email,
      role: input.role,
      hotel_id: input.hotel_id,
      scope: input.hotel_id ? "hotel" : "global",
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    })
  );
  const signature = createHmac("sha256", getSecret())
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

export function verifyAccessToken(token: string): AccessClaims {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new AppError(401, "Invalid token", "Unauthorized");
  }
  const [header, payload, signature] = parts;
  const expected = createHmac("sha256", getSecret())
    .update(`${header}.${payload}`)
    .digest();
  const actual = Buffer.from(signature, "base64url");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new AppError(401, "Invalid token", "Unauthorized");
  }
  const claims = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  ) as AccessClaims;
  if (!claims.sub || !claims.exp || Date.now() / 1000 > claims.exp) {
    throw new AppError(401, "Token expired", "Unauthorized");
  }
  return claims;
}

/** Refresh opaco: se guarda solo su hash SHA-256, nunca el valor. */
export function newRefreshToken(): string {
  return randomBytes(32).toString("hex");
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

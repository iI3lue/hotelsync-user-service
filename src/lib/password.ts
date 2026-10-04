import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const KEY_LENGTH = 64;

/**
 * Hash de contrasena con scrypt (stdlib, sin dependencias).
 * Formato: `scrypt$<salt hex>$<derived hex>`.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const derived = (await scrypt(password, salt, KEY_LENGTH)) as Buffer;
  return `scrypt$${salt}$${derived.toString("hex")}`;
}

export async function verifyPassword(
  password: string,
  stored: string
): Promise<boolean> {
  const [scheme, salt, expected] = stored.split("$");
  if (scheme !== "scrypt" || !salt || !expected) return false;
  const derived = (await scrypt(password, salt, KEY_LENGTH)) as Buffer;
  const expectedBuffer = Buffer.from(expected, "hex");
  return (
    derived.length === expectedBuffer.length &&
    timingSafeEqual(derived, expectedBuffer)
  );
}

/** Contrasena temporal para altas de personal (se muestra una sola vez). */
export function randomTempPassword(): string {
  return randomBytes(9).toString("base64url");
}

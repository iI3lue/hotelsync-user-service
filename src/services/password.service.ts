import { createHash, randomBytes, randomInt } from "node:crypto";
import prisma from "../lib/prisma.js";
import { AppError } from "../middleware/error-handler.js";
import { hashPassword } from "../lib/password.js";
import { isDemoResetExposed, sendPasswordResetEmail } from "../lib/mailer.js";
import { checkRateLimit } from "../lib/rate-limit.js";
import {
  ForgotPasswordInput,
  RequestCodeInput,
  ResetPasswordInput,
} from "../validators/auth.js";

export const RESET_TTL_MS = 60 * 60 * 1000;
const RESET_MAX_PER_WINDOW = 5;
const RESET_WINDOW_MS = 10 * 60 * 1000;

// Flujo demo por código en pantalla (opción C): 6 dígitos, 10 min de vida,
// 5 intentos por IP cada 10 min. Con 1M de combinaciones, adivinarlo en la
// ventana es inviable (5 intentos / 1M por IP y ventana).
export const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_MAX_ATTEMPTS_PER_WINDOW = 5;
const CODE_WINDOW_MS = 10 * 60 * 1000;

function newDemoCode(): string {
  return String(randomInt(100000, 1000000));
}

function resetBaseUrl(): string {
  return process.env.PASSWORD_RESET_BASE_URL ?? "http://localhost:3000";
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function isFederatedOnly(passwordHash: string): boolean {
  return passwordHash.startsWith("federated$");
}

export class PasswordService {
  /**
   * Emite un enlace de recuperación. Siempre devuelve ok, exista o no la
   * cuenta, esté activa o sea federada: revelar la diferencia permitiría
   * enumerar emails registrados.
   */
  async requestReset(data: ForgotPasswordInput) {
    const email = data.email;
    if (
      !checkRateLimit(
        `pwreset:${email}`,
        RESET_MAX_PER_WINDOW,
        RESET_WINDOW_MS
      )
    ) {
      throw new AppError(
        429,
        "Demasiados intentos, probá más tarde",
        "Too Many Requests"
      );
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.status !== "ACTIVE") return { ok: true };
    if (isFederatedOnly(user.password_hash)) {
      console.log(
        `[password] cuenta federada ${email}: entra con Google, sin reset.`
      );
      return { ok: true };
    }

    const token = randomBytes(32).toString("hex");
    await prisma.$transaction(async (tx) => {
      // Un solo link vigente: los anteriores quedan invalidados.
      await tx.passwordResetToken.updateMany({
        where: { user_id: user.user_id, used_at: null },
        data: { used_at: new Date() },
      });
      await tx.passwordResetToken.create({
        data: {
          user_id: user.user_id,
          token_hash: hashToken(token),
          expires_at: new Date(Date.now() + RESET_TTL_MS),
        },
      });
    });

    await sendPasswordResetEmail({
      to: user.email,
      resetUrl: `${resetBaseUrl()}/cuenta/restablecer?token=${token}`,
      expiresMinutes: RESET_TTL_MS / 60000,
    });
    return { ok: true };
  }

  /**
   * Emite un código demo de 6 dígitos para mostrar en pantalla (opción C).
   * Mismas reglas de privacidad que forgot: siempre ok. El código solo se
   * devuelve con el mailer `log` (dev); con `smtp` viaja por email y la
   * respuesta no lo incluye.
   */
  async requestCode(data: RequestCodeInput) {
    const email = data.email;
    if (
      !checkRateLimit(`pwcode:${email}`, RESET_MAX_PER_WINDOW, RESET_WINDOW_MS)
    ) {
      throw new AppError(
        429,
        "Demasiados intentos, probá más tarde",
        "Too Many Requests"
      );
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.status !== "ACTIVE") return { ok: true };
    if (isFederatedOnly(user.password_hash)) {
      console.log(
        `[password] cuenta federada ${email}: entra con Google, sin código.`
      );
      return { ok: true };
    }

    const code = newDemoCode();
    await prisma.$transaction(async (tx) => {
      await tx.passwordResetToken.updateMany({
        where: { user_id: user.user_id, used_at: null },
        data: { used_at: new Date() },
      });
      await tx.passwordResetToken.create({
        data: {
          user_id: user.user_id,
          token_hash: hashToken(code),
          expires_at: new Date(Date.now() + CODE_TTL_MS),
        },
      });
    });
    console.log(
      `[password:demo] código para ${email} (expira en ${
        CODE_TTL_MS / 60000
      } min)`
    );
    if (!isDemoResetExposed()) return { ok: true };
    return { ok: true, demo_code: code };
  }

  /**
   * Canjea el token (link) o código (demo) por una contraseña nueva (un solo
   * uso). Rota el hash y revoca todas las sesiones: si alguien había entrado
   * con la clave vieja, queda expulsado.
   */
  async resetPassword(data: ResetPasswordInput, ip = "unknown") {
    if (
      !checkRateLimit(
        `pwreset-attempt:${ip}`,
        CODE_MAX_ATTEMPTS_PER_WINDOW,
        CODE_WINDOW_MS
      )
    ) {
      throw new AppError(
        429,
        "Demasiados intentos, probá más tarde",
        "Too Many Requests"
      );
    }
    const record = await prisma.passwordResetToken.findUnique({
      where: { token_hash: hashToken(data.token) },
      include: { user: true },
    });
    if (
      !record ||
      record.used_at ||
      record.expires_at.getTime() < Date.now() ||
      record.user.status !== "ACTIVE"
    ) {
      throw new AppError(400, "Enlace inválido o vencido", "Bad Request");
    }

    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { user_id: record.user_id },
        data: { password_hash: await hashPassword(data.new_password) },
      });
      await tx.passwordResetToken.update({
        where: { token_id: record.token_id },
        data: { used_at: new Date() },
      });
      await tx.refreshSession.updateMany({
        where: { user_id: record.user_id, revoked_at: null },
        data: { revoked_at: new Date() },
      });
    });
    return { ok: true };
  }
}

export const passwordService = new PasswordService();

export interface PasswordResetMail {
  to: string;
  resetUrl: string;
  expiresMinutes: number;
}

/**
 * Proveedor de mail por entorno: `log` (dev, default) o `smtp` (real).
 * El flujo demo por código solo expone el código con el proveedor `log`;
 * con `smtp` el código nunca sale en la respuesta (viajaría por email).
 */
export function isLogMailer(): boolean {
  return (process.env.MAILER_PROVIDER ?? "log") === "log";
}

/**
 * Expone el código (respuesta HTTP) y el enlace (log) de recuperación solo con
 * un opt-in explícito en modo `log`. Apagado por defecto: sin SMTP configurado,
 * exponerlos permitiría resetear la contraseña de cualquier cuenta con solo
 * conocer el email.
 */
export function isDemoResetExposed(): boolean {
  return isLogMailer() && process.env.PASSWORD_RESET_DEMO_CODE === "true";
}

/**
 * Envío de emails en modo dev: el enlace queda en el log del servicio.
 * Para producción, reemplazar el cuerpo por nodemailer (SMTP) u otro
 * proveedor guiado por MAILER_PROVIDER, sin cambiar a los llamadores.
 */
export async function sendPasswordResetEmail(
  mail: PasswordResetMail
): Promise<void> {
  if (!isDemoResetExposed()) {
    console.log(
      `[mailer] recuperación solicitada para ${mail.to}: sin proveedor de ` +
        `envío configurado, el enlace no se registra.`
    );
    return;
  }
  console.log(
    `[mailer:dev] enlace de recuperación para ${mail.to} ` +
      `(expira en ${mail.expiresMinutes} min): ${mail.resetUrl}`
  );
}

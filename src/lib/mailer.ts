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
 * Envío de emails en modo dev: el enlace queda en el log del servicio.
 * Para producción, reemplazar el cuerpo por nodemailer (SMTP) u otro
 * proveedor guiado por MAILER_PROVIDER, sin cambiar a los llamadores.
 */
export async function sendPasswordResetEmail(
  mail: PasswordResetMail
): Promise<void> {
  console.log(
    `[mailer:dev] enlace de recuperación para ${mail.to} ` +
      `(expira en ${mail.expiresMinutes} min): ${mail.resetUrl}`
  );
}

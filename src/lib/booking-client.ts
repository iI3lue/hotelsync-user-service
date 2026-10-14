import { AppError } from "../middleware/error-handler.js";

const BOOKING_SERVICE_URL =
  process.env.BOOKING_SERVICE_URL || "http://localhost:3004/v1";
const BOOKING_SERVICE_KEY = process.env.BOOKING_SERVICE_KEY || "";

/**
 * ¿La cuenta tiene reservas activas? (baja de cuentas, variante A).
 * Fail-closed: cualquier fallo de Booking (red, 5xx, ruta ausente) se
 * traduce en 503 y la baja NO se ejecuta. Nunca se permite borrar sin
 * haber verificado.
 */
export async function hasActiveBookings(userId: string): Promise<boolean> {
  const url = `${BOOKING_SERVICE_URL}/bookings/by-user/${userId}/has-active`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: BOOKING_SERVICE_KEY
        ? { "x-user-key": BOOKING_SERVICE_KEY }
        : {},
    });
  } catch {
    throw new AppError(503, "Booking service unavailable", "Bad Gateway");
  }
  if (!res.ok) {
    throw new AppError(503, "Booking service unavailable", "Bad Gateway");
  }
  const data = (await res.json()) as { has_active?: boolean };
  return data.has_active === true;
}

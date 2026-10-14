/**
 * Rate-limit en memoria por clave (proceso local, alcance académico).
 * En producción con varias réplicas corresponde Redis o similar.
 */
const hits = new Map<string, number[]>();

export function checkRateLimit(
  key: string,
  max: number,
  windowMs: number
): boolean {
  const now = Date.now();
  const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  if (recent.length >= max) {
    hits.set(key, recent);
    return false;
  }
  recent.push(now);
  hits.set(key, recent);
  return true;
}

/** Solo para tests: limpia el estado en memoria. */
export function clearRateLimits(): void {
  hits.clear();
}

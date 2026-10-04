import { Request, Response, NextFunction } from "express";
import { AppError } from "./error-handler.js";
import { AccessClaims, verifyAccessToken } from "../lib/tokens.js";

export interface AuthRequest extends Request {
  auth?: AccessClaims;
}

function bearerToken(req: Request): string {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    throw new AppError(401, "Missing bearer token", "Unauthorized");
  }
  return header.slice("Bearer ".length).trim();
}

/** Exige un access token valido y lo deja en `req.auth`. */
export function requireAuth(
  req: Request,
  _res: Response,
  next: NextFunction
): void {
  try {
    (req as AuthRequest).auth = verifyAccessToken(bearerToken(req));
    next();
  } catch (err) {
    next(err);
  }
}

/** Exige uno de los roles indicados (requiere `requireAuth` antes). */
export function requireRole(...roles: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const auth = (req as AuthRequest).auth;
    if (!auth) {
      next(new AppError(401, "Missing bearer token", "Unauthorized"));
      return;
    }
    if (!roles.includes(auth.role)) {
      next(new AppError(403, "Insufficient role", "Forbidden"));
      return;
    }
    next();
  };
}

export const requireSuperAdmin = requireRole("SUPER_ADMIN");

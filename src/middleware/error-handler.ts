import { Request, Response, NextFunction } from "express";

export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public error: string = "Error"
  ) {
    super(message);
    this.name = "AppError";
  }
}

// Errores del cliente que express/body-parser marcan con statusCode (p. ej. JSON malformado, 400).
type HttpLikeError = Error & { statusCode?: number; status?: number; expose?: boolean; type?: string };

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: err.error,
      message: err.message,
      statusCode: err.statusCode,
    });
    return;
  }

  const httpErr = err as HttpLikeError;
  const status = httpErr.statusCode ?? httpErr.status;

  if (status && status >= 400 && status < 500 && httpErr.expose) {
    res.status(status).json({
      error: "Bad Request",
      message: "Invalid request body or parameters",
      statusCode: status,
    });
    return;
  }

  // Solo mensaje y stack: nunca el objeto completo (incluye el body de la petición).
  console.error("Unhandled error:", err.message, err.stack);
  res.status(500).json({
    error: "Internal Server Error",
    message: "An unexpected error occurred",
    statusCode: 500,
  });
}
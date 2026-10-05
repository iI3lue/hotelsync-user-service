import { AppError } from "../middleware/error-handler.js";

type JoseModule = typeof import("jose", {
  with: { "resolution-mode": "import" },
});

/**
 * Identidades federadas vía Auth0 (que intermedia Google). El front completa
 * el flujo OAuth y envía el ID token; aquí se verifica firma, emisor y
 * audiencia contra el JWKS de Auth0. Nunca se acepta un `sub` sin firmar.
 */
export const FEDERATED_PROVIDERS = ["auth0"] as const;

export interface FederatedClaims {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

let jose: JoseModule | null = null;
let jwks: ReturnType<JoseModule["createRemoteJWKSet"]> | null = null;

async function jwksFor(domain: string) {
  jose ??= (await import("jose")) as JoseModule;
  jwks ??= jose.createRemoteJWKSet(
    new URL(`https://${domain}/.well-known/jwks.json`)
  );
  return { jose: jose as JoseModule, jwks };
}

export async function verifyAuth0IdToken(
  idToken: string,
  expectedNonce: string
): Promise<FederatedClaims> {
  const domain = process.env.AUTH0_DOMAIN;
  const audience = process.env.AUTH0_CLIENT_ID;
  if (!domain || !audience) {
    throw new AppError(
      503,
      "Social login is not configured",
      "Service Unavailable"
    );
  }

  const { jose: joseLib, jwks: keySet } = await jwksFor(domain);

  try {
    const { payload } = await joseLib.jwtVerify(idToken, keySet, {
      issuer: `https://${domain}/`,
      audience,
    });
    if (!payload.sub || typeof payload.sub !== "string") {
      console.error("[federated] id_token rejected (missing sub)");
      throw new AppError(401, "Invalid federated token", "Unauthorized");
    }
    if (payload.nonce !== expectedNonce) {
      console.error("[federated] id_token rejected (nonce mismatch)");
      throw new AppError(401, "Invalid federated token", "Unauthorized");
    }
    return {
      sub: payload.sub,
      email: typeof payload.email === "string" ? payload.email : undefined,
      emailVerified: payload.email_verified === true,
      name: typeof payload.name === "string" ? payload.name : undefined,
    };
  } catch (err) {
    if (err instanceof AppError) throw err;
    const code =
      err instanceof Error
        ? ((err as { code?: string }).code ?? err.name)
        : "unknown";
    console.error(`[federated] id_token rejected (${code})`);
    throw new AppError(401, "Invalid federated token", "Unauthorized");
  }
}

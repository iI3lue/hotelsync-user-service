import prisma from "../lib/prisma.js";
import { AppError } from "../middleware/error-handler.js";
import {
  hashPassword,
  randomTempPassword,
  verifyPassword,
} from "../lib/password.js";
import {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  hashRefreshToken,
  newRefreshToken,
  signAccessToken,
} from "../lib/tokens.js";
import { verifyAuth0IdToken } from "../lib/federated.js";
import {
  FederatedInput,
  LoginInput,
  RegisterInput,
  UpdateMeInput,
} from "../validators/auth.js";

function publicProfile(user: {
  user_id: string;
  email: string;
  name: string;
  phone: string | null;
  status: string;
  email_verified: boolean;
}) {
  return {
    user_id: user.user_id,
    email: user.email,
    name: user.name,
    phone: user.phone,
    status: user.status,
    email_verified: user.email_verified,
  };
}

async function activeAssignment(userId: string) {
  return prisma.roleAssignment.findFirst({
    where: { user_id: userId, is_active: true },
    orderBy: { created_at: "desc" },
  });
}

async function issueSession(userId: string) {
  const refreshToken = newRefreshToken();
  const session = await prisma.refreshSession.create({
    data: {
      user_id: userId,
      token_hash: hashRefreshToken(refreshToken),
      expires_at: new Date(Date.now() + REFRESH_TTL_SECONDS * 1000),
    },
  });
  return { refreshToken, session };
}

export class AuthService {
  /** Registro publico opcional: siempre crea cuenta GUEST activa. */
  async register(data: RegisterInput) {
    const existing = await prisma.user.findUnique({
      where: { email: data.email },
      select: { user_id: true },
    });
    if (existing) {
      throw new AppError(409, "Email already registered", "Conflict");
    }

    const user = await prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          email: data.email,
          password_hash: await hashPassword(data.password),
          name: data.name,
          phone: data.phone,
          status: "ACTIVE",
        },
      });
      await tx.roleAssignment.create({
        data: { user_id: created.user_id, role: "GUEST", hotel_id: null },
      });
      return created;
    });

    const assignment = await activeAssignment(user.user_id);
    const { refreshToken } = await issueSession(user.user_id);
    return {
      access_token: signAccessToken({
        sub: user.user_id,
        email: user.email,
        role: "GUEST",
        hotel_id: null,
      }),
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      user: publicProfile(user),
      assignment,
    };
  }

  async login(data: LoginInput) {
    const user = await prisma.user.findUnique({
      where: { email: data.email },
    });
    if (!user || !(await verifyPassword(data.password, user.password_hash))) {
      throw new AppError(401, "Invalid credentials", "Unauthorized");
    }
    if (user.status !== "ACTIVE") {
      throw new AppError(403, `Account is ${user.status}`, "Forbidden");
    }
    const assignment = await activeAssignment(user.user_id);
    if (!assignment) {
      throw new AppError(403, "Account has no active role", "Forbidden");
    }

    const { refreshToken } = await issueSession(user.user_id);
    return {
      access_token: signAccessToken({
        sub: user.user_id,
        email: user.email,
        role: assignment.role,
        hotel_id: assignment.hotel_id,
      }),
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      user: publicProfile(user),
      assignment,
    };
  }

  /** Rotacion: revoca el refresh usado y emite un par nuevo. */
  async refresh(refreshToken: string) {
    const session = await prisma.refreshSession.findUnique({
      where: { token_hash: hashRefreshToken(refreshToken) },
      include: { user: true },
    });
    if (
      !session ||
      session.revoked_at ||
      session.expires_at.getTime() < Date.now() ||
      session.user.status !== "ACTIVE"
    ) {
      throw new AppError(401, "Invalid refresh token", "Unauthorized");
    }
    const assignment = await activeAssignment(session.user_id);
    if (!assignment) {
      throw new AppError(403, "Account has no active role", "Forbidden");
    }

    const created = await issueSession(session.user_id);
    await prisma.refreshSession.update({
      where: { session_id: session.session_id },
      data: { revoked_at: new Date(), replaced_by: created.session.session_id },
    });

    return {
      access_token: signAccessToken({
        sub: session.user_id,
        email: session.user.email,
        role: assignment.role,
        hotel_id: assignment.hotel_id,
      }),
      refresh_token: created.refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      user: publicProfile(session.user),
      assignment,
    };
  }

  /**
   * Login federado (Google vía Auth0). Busca la identidad externa; si no
   * existe, crea cuenta GUEST. Nunca vincula por email coincidente (eso
   * permitiría tomar cuentas ajenas): el email existente con contraseña
   * devuelve 409 indicando entrar con contraseña.
   */
  async federated(data: FederatedInput) {
    const claims = await verifyAuth0IdToken(data.id_token);
    if (!claims.email) {
      throw new AppError(
        400,
        "Federated identity has no email",
        "Bad Request"
      );
    }

    const identity = await prisma.externalIdentity.findUnique({
      where: {
        provider_provider_sub: { provider: data.provider, provider_sub: claims.sub },
      },
      include: { user: true },
    });

    if (identity) {
      if (identity.user.status !== "ACTIVE") {
        throw new AppError(403, `Account is ${identity.user.status}`, "Forbidden");
      }
      const assignment = await activeAssignment(identity.user_id);
      if (!assignment) {
        throw new AppError(403, "Account has no active role", "Forbidden");
      }
      const { refreshToken } = await issueSession(identity.user_id);
      return {
        access_token: signAccessToken({
          sub: identity.user_id,
          email: identity.user.email,
          role: assignment.role,
          hotel_id: assignment.hotel_id,
        }),
        refresh_token: refreshToken,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECONDS,
        user: publicProfile(identity.user),
        assignment,
      };
    }

    const existing = await prisma.user.findUnique({
      where: { email: claims.email },
      select: { user_id: true },
    });
    if (existing) {
      throw new AppError(
        409,
        "Email already registered with password, sign in to link",
        "Conflict"
      );
    }

    const user = await prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          email: claims.email as string,
          // Sin contraseña utilizable: el esquema "federated$" nunca verifica.
          password_hash: `federated$${randomTempPassword()}`,
          name: claims.name?.trim() || claims.email as string,
          status: "ACTIVE",
          email_verified: claims.emailVerified ?? false,
        },
      });
      await tx.roleAssignment.create({
        data: { user_id: created.user_id, role: "GUEST", hotel_id: null },
      });
      await tx.externalIdentity.create({
        data: {
          user_id: created.user_id,
          provider: data.provider,
          provider_sub: claims.sub,
          email: claims.email,
        },
      });
      return created;
    });

    const assignment = await activeAssignment(user.user_id);
    const { refreshToken } = await issueSession(user.user_id);
    return {
      access_token: signAccessToken({
        sub: user.user_id,
        email: user.email,
        role: "GUEST",
        hotel_id: null,
      }),
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL_SECONDS,
      user: publicProfile(user),
      assignment,
    };
  }

  /** Idempotente: revocar dos veces sigue devolviendo 200. */
  async logout(refreshToken: string) {
    await prisma.refreshSession.updateMany({
      where: {
        token_hash: hashRefreshToken(refreshToken),
        revoked_at: null,
      },
      data: { revoked_at: new Date() },
    });
    return { logged_out: true };
  }

  async getMe(userId: string) {
    const user = await prisma.user.findUnique({
      where: { user_id: userId },
    });
    if (!user) {
      throw new AppError(404, `User with id ${userId} not found`, "Not Found");
    }
    const assignment = await activeAssignment(user.user_id);
    return { user: publicProfile(user), assignment };
  }

  async updateMe(userId: string, data: UpdateMeInput) {
    const user = await prisma.user.update({
      where: { user_id: userId },
      data: {
        ...(data.name ? { name: data.name } : {}),
        ...(data.phone ? { phone: data.phone } : {}),
      },
    }).catch(() => {
      throw new AppError(404, `User with id ${userId} not found`, "Not Found");
    });
    return publicProfile(user);
  }
}

export const authService = new AuthService();

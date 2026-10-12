import prisma from "../lib/prisma.js";
import { AppError } from "../middleware/error-handler.js";
import { hashPassword, randomTempPassword } from "../lib/password.js";
import { AccessClaims } from "../lib/tokens.js";
import {
  CreateHotelStaffInput,
  CreateStaffInput,
  HOTEL_ROLES,
  ListStaffQuery,
  SetHotelStaffActiveInput,
  UpdateStaffInput,
} from "../validators/auth.js";

function isSuperAdmin(actor: AccessClaims): boolean {
  return actor.role === "SUPER_ADMIN";
}

/**
 * Revoca todas las sesiones activas de un usuario. Se usa al desactivar
 * la cuenta o una asignación: el access token vive 15 minutos, así que
 * sin esto el permiso retirado seguiría válido hasta su expiración.
 */
async function revokeUserSessions(userId: string): Promise<void> {
  await prisma.refreshSession.updateMany({
    where: { user_id: userId, revoked_at: null },
    data: { revoked_at: new Date() },
  });
}

function publicProfile(user: {
  user_id: string;
  email: string;
  name: string;
  phone: string | null;
  picture_url: string | null;
  status: string;
  email_verified: boolean;
}) {
  return {
    user_id: user.user_id,
    email: user.email,
    name: user.name,
    phone: user.phone,
    picture_url: user.picture_url,
    status: user.status,
    email_verified: user.email_verified,
  };
}

export class UserService {
  /**
   * Alta de personal (solo SUPER_ADMIN). Sin proveedor de correo: si no se
   * indica contrasena se genera una temporal y se devuelve una sola vez.
   */
  async createStaff(actor: AccessClaims, data: CreateStaffInput) {
    if (!isSuperAdmin(actor)) {
      throw new AppError(403, "Only SUPER_ADMIN can manage staff", "Forbidden");
    }

    const needsHotel = (HOTEL_ROLES as readonly string[]).includes(data.role);
    if (needsHotel && !data.hotel_id) {
      throw new AppError(400, `Role ${data.role} requires hotel_id`, "Bad Request");
    }
    if (!needsHotel && data.hotel_id) {
      throw new AppError(
        400,
        `Role ${data.role} is global and takes no hotel_id`,
        "Bad Request"
      );
    }

    const existing = await prisma.user.findUnique({
      where: { email: data.email },
      select: { user_id: true },
    });
    if (existing) {
      throw new AppError(409, "Email already registered", "Conflict");
    }

    const created = await this.createUserWithRole({
      email: data.email,
      password: data.password,
      name: data.name,
      phone: data.phone,
      role: data.role,
      hotel_id: data.hotel_id ?? null,
    });

    return {
      user: publicProfile(created.user),
      ...(created.initialPassword ? { initial_password: created.initialPassword } : {}),
    };
  }

  /**
   * Alta de personal acotada a un hotel: SUPER_ADMIN en cualquiera,
   * MANAGER solo en el suyo y solo roles operativos (no crea managers).
   */
  async createHotelStaff(
    actor: AccessClaims,
    hotelId: string,
    data: CreateHotelStaffInput
  ) {
    this.requireHotelScope(actor, hotelId);
    const created = await this.createUserWithRole({
      ...data,
      hotel_id: hotelId,
    });
    return {
      user: publicProfile(created.user),
      ...(created.initialPassword ? { initial_password: created.initialPassword } : {}),
    };
  }

  /** Personal activo de un hotel (mismo alcance que el alta). */
  async listHotelStaff(actor: AccessClaims, hotelId: string, role?: string) {
    this.requireHotelScope(actor, hotelId);
    const users = await prisma.user.findMany({
      where: {
        assignments: {
          some: {
            is_active: true,
            hotel_id: hotelId,
            ...(role ? { role } : {}),
          },
        },
      },
      include: {
        assignments: { where: { is_active: true, hotel_id: hotelId } },
      },
      orderBy: { created_at: "asc" },
    });
    return users.map((user) => ({
      ...publicProfile(user),
      assignments: user.assignments,
    }));
  }

  /**
   * Activa/desactiva la asignacion hotel-usuario (no toca la cuenta global).
   * Nunca sobre roles SUPER_ADMIN ni sobre uno mismo.
   */
  async setHotelStaffActive(
    actor: AccessClaims,
    hotelId: string,
    userId: string,
    data: SetHotelStaffActiveInput
  ) {
    this.requireHotelScope(actor, hotelId);
    if (userId === actor.sub) {
      throw new AppError(409, "Cannot change your own assignment", "Conflict");
    }
    const assignment = await prisma.roleAssignment.findFirst({
      where: { user_id: userId, hotel_id: hotelId, is_active: true },
    });
    if (!assignment) {
      throw new AppError(404, "Staff assignment not found for this hotel", "Not Found");
    }
    if (assignment.role === "SUPER_ADMIN") {
      throw new AppError(403, "Cannot modify SUPER_ADMIN assignments", "Forbidden");
    }
    const updated = await prisma.roleAssignment.update({
      where: { assignment_id: assignment.assignment_id },
      data: { is_active: data.is_active },
    });
    if (!data.is_active) {
      await revokeUserSessions(userId);
    }
    return updated;
  }

  private requireHotelScope(actor: AccessClaims, hotelId: string): void {
    if (isSuperAdmin(actor)) return;
    if (actor.role !== "MANAGER" || actor.hotel_id !== hotelId) {
      throw new AppError(403, "Manager of this hotel required", "Forbidden");
    }
  }

  private async createUserWithRole(data: {
    email: string;
    password?: string;
    name: string;
    phone?: string;
    role: string;
    hotel_id: string | null;
  }) {
    const existing = await prisma.user.findUnique({
      where: { email: data.email },
      select: { user_id: true },
    });
    if (existing) {
      throw new AppError(409, "Email already registered", "Conflict");
    }

    const initialPassword = data.password ?? randomTempPassword();
    const user = await prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: {
          email: data.email,
          password_hash: await hashPassword(initialPassword),
          name: data.name,
          phone: data.phone,
          status: "ACTIVE",
        },
      });
      await tx.roleAssignment.create({
        data: {
          user_id: created.user_id,
          role: data.role,
          hotel_id: data.hotel_id,
        },
      });
      return created;
    });

    return {
      user,
      initialPassword: data.password ? undefined : initialPassword,
    };
  }

  /**
   * SUPER_ADMIN ve todo; MANAGER solo su hotel (el filtro se fuerza).
   */
  async listStaff(actor: AccessClaims, query: ListStaffQuery) {
    const hotelId =
      actor.role === "MANAGER" ? actor.hotel_id : query.hotel_id ?? undefined;
    if (!isSuperAdmin(actor) && actor.role !== "MANAGER") {
      throw new AppError(403, "Insufficient role", "Forbidden");
    }

    const users = await prisma.user.findMany({
      where: {
        assignments: {
          some: {
            is_active: true,
            ...(hotelId ? { hotel_id: hotelId } : {}),
            ...(query.role ? { role: query.role } : {}),
          },
        },
      },
      include: {
        assignments: {
          where: {
            is_active: true,
            // Un MANAGER solo ve las asignaciones de su propio hotel;
            // SUPER_ADMIN ve todas las activas.
            ...(hotelId && actor.role === "MANAGER" ? { hotel_id: hotelId } : {}),
          },
        },
      },
      orderBy: { created_at: "asc" },
    });
    return users.map((user) => ({
      ...publicProfile(user),
      assignments: user.assignments,
    }));
  }

  /** Solo SUPER_ADMIN. No permite desactivarse a si mismo. */
  async updateStaff(actor: AccessClaims, id: string, data: UpdateStaffInput) {
    if (!isSuperAdmin(actor)) {
      throw new AppError(403, "Only SUPER_ADMIN can manage staff", "Forbidden");
    }
    if (id === actor.sub && data.status && data.status !== "ACTIVE") {
      throw new AppError(409, "Cannot deactivate your own account", "Conflict");
    }

    const user = await prisma.user.update({
      where: { user_id: id },
      data: {
        ...(data.name ? { name: data.name } : {}),
        ...(data.phone ? { phone: data.phone } : {}),
        ...(data.status ? { status: data.status } : {}),
      },
    }).catch(() => {
      throw new AppError(404, `User with id ${id} not found`, "Not Found");
    });
    if (data.status && data.status !== "ACTIVE") {
      await revokeUserSessions(id);
    }
    return publicProfile(user);
  }
}

export const userService = new UserService();

import { z } from "zod";

export const ROLES = [
  "SUPER_ADMIN",
  "MANAGER",
  "RECEPTIONIST",
  "HOUSEKEEPER",
  "GUEST",
] as const;

export const USER_STATUSES = [
  "INVITED",
  "ACTIVE",
  "LOCKED",
  "DISABLED",
] as const;

/** Roles atados a un hotel concreto. */
export const HOTEL_ROLES = ["MANAGER", "RECEPTIONIST", "HOUSEKEEPER"] as const;

/** Roles que un MANAGER puede dar de alta en su hotel. */
export const MANAGER_CREATABLE_ROLES = ["RECEPTIONIST", "HOUSEKEEPER"] as const;

const emailSchema = z.string().trim().toLowerCase().email().max(255);
const passwordSchema = z.string().min(8).max(128);

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().trim().min(1).max(255),
  phone: z.string().trim().min(1).max(50).optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});

export const refreshSchema = z.object({
  refresh_token: z.string().min(1).max(256),
});

export const logoutSchema = refreshSchema;

export const federatedSchema = z.object({
  provider: z.literal("auth0"),
  id_token: z.string().min(1).max(8192),
});

export const updateMeSchema = z.object({
  name: z.string().trim().min(1).max(255).optional(),
  phone: z.string().trim().min(1).max(50).optional(),
});

export const userIdParamSchema = z.object({
  id: z.string().uuid(),
});

export const createStaffSchema = z.object({
  email: emailSchema,
  password: passwordSchema.optional(),
  name: z.string().trim().min(1).max(255),
  phone: z.string().trim().min(1).max(50).optional(),
  role: z.enum(ROLES),
  hotel_id: z.string().uuid().optional(),
});

export const updateStaffSchema = z.object({
  name: z.string().trim().min(1).max(255).optional(),
  phone: z.string().trim().min(1).max(50).optional(),
  status: z.enum(USER_STATUSES).optional(),
});

export const listStaffQuerySchema = z.object({
  hotel_id: z.string().uuid().optional(),
  role: z.enum(ROLES).optional(),
});

export const hotelIdParamSchema = z.object({
  hotelId: z.string().uuid(),
});

export const hotelStaffIdParamSchema = z.object({
  hotelId: z.string().uuid(),
  userId: z.string().uuid(),
});

export const createHotelStaffSchema = z.object({
  email: emailSchema,
  password: passwordSchema.optional(),
  name: z.string().trim().min(1).max(255),
  phone: z.string().trim().min(1).max(50).optional(),
  role: z.enum(MANAGER_CREATABLE_ROLES),
});

export const setHotelStaffActiveSchema = z.object({
  is_active: z.boolean(),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
export type FederatedInput = z.infer<typeof federatedSchema>;
export type UpdateMeInput = z.infer<typeof updateMeSchema>;
export type CreateStaffInput = z.infer<typeof createStaffSchema>;
export type UpdateStaffInput = z.infer<typeof updateStaffSchema>;
export type ListStaffQuery = z.infer<typeof listStaffQuerySchema>;
export type CreateHotelStaffInput = z.infer<typeof createHotelStaffSchema>;
export type SetHotelStaffActiveInput = z.infer<typeof setHotelStaffActiveSchema>;

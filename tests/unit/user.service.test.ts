import { userService } from "../../src/services/user.service.js";
import { AppError } from "../../src/middleware/error-handler.js";
import { AccessClaims } from "../../src/lib/tokens.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn(), findMany: jest.fn(), update: jest.fn() },
    roleAssignment: {
      create: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
    },
    refreshSession: { updateMany: jest.fn() },
    $transaction: jest.fn(),
  },
}));

import prisma from "../../src/lib/prisma.js";

const mockPrisma = prisma as any;
const ADMIN_ID = "00000000-0000-4000-8000-000000000001";
const HOTEL_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

const superAdmin: AccessClaims = {
  sub: ADMIN_ID,
  email: "admin@hotelsync.local",
  email_verified: true,
  role: "SUPER_ADMIN",
  hotel_id: null,
  scope: "global",
  iss: "hotelsync",
  aud: "hotelsync-api",
  iat: 0,
  exp: 9999999999,
};

const manager: AccessClaims = {
  sub: "11111111-2222-4333-8444-555555555555",
  email: "manager@example.com",
  email_verified: true,
  role: "MANAGER",
  hotel_id: HOTEL_ID,
  scope: "hotel",
  iss: "hotelsync",
  aud: "hotelsync-api",
  iat: 0,
  exp: 9999999999,
};

describe("UserService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("createStaff", () => {
    it("creates staff with a one-time temp password when none is given", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const created = {
        user_id: "22222222-2222-4333-8444-555555555555",
        email: "recep@example.com",
        name: "Recep",
        phone: null,
        status: "ACTIVE",
        email_verified: false,
      };
      mockPrisma.$transaction.mockImplementation((callback: any) =>
        callback({
          user: { create: jest.fn().mockResolvedValue(created) },
          roleAssignment: { create: jest.fn().mockResolvedValue({}) },
        })
      );

      const result = await userService.createStaff(superAdmin, {
        email: "recep@example.com",
        name: "Recep",
        role: "RECEPTIONIST",
        hotel_id: HOTEL_ID,
      });

      expect(result.user.email).toBe("recep@example.com");
      expect(result.initial_password).toBeDefined();
    });

    it("requires hotel_id for hotel-scoped roles", async () => {
      await expect(
        userService.createStaff(superAdmin, {
          email: "x@example.com",
          name: "X",
          role: "HOUSEKEEPER",
        })
      ).rejects.toThrow(AppError);
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it("rejects non-admin actors", async () => {
      await expect(
        userService.createStaff(manager, {
          email: "x@example.com",
          name: "X",
          role: "RECEPTIONIST",
          hotel_id: HOTEL_ID,
        })
      ).rejects.toThrow(AppError);
    });
  });

  describe("listStaff", () => {
    it("forces the manager scope to their own hotel", async () => {
      mockPrisma.user.findMany.mockResolvedValue([]);

      await userService.listStaff(manager, {
        hotel_id: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
      });

      expect(mockPrisma.user.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            assignments: expect.objectContaining({
              some: expect.objectContaining({ hotel_id: HOTEL_ID }),
            }),
          }),
        })
      );
    });
  });

  describe("updateStaff", () => {
    it("prevents self-deactivation", async () => {
      await expect(
        userService.updateStaff(superAdmin, ADMIN_ID, { status: "DISABLED" })
      ).rejects.toThrow(AppError);
      expect(mockPrisma.user.update).not.toHaveBeenCalled();
    });

    it("revokes sessions when disabling an account", async () => {
      mockPrisma.user.update.mockResolvedValue({ status: "DISABLED" });

      await userService.updateStaff(superAdmin, "some-user", {
        status: "DISABLED",
      });

      expect(mockPrisma.refreshSession.updateMany).toHaveBeenCalledWith({
        where: { user_id: "some-user", revoked_at: null },
        data: expect.objectContaining({ revoked_at: expect.any(Date) }),
      });
    });

    it("keeps sessions when the account stays active", async () => {
      mockPrisma.user.update.mockResolvedValue({ status: "ACTIVE" });

      await userService.updateStaff(superAdmin, "some-user", {
        name: "New Name",
      });

      expect(mockPrisma.refreshSession.updateMany).not.toHaveBeenCalled();
    });
  });

  describe("hotel staff (manager scope)", () => {
    it("lets a manager create staff in their own hotel", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const created = {
        user_id: "33333333-3333-4333-8444-555555555555",
        email: "hk@example.com",
        name: "HK",
        phone: null,
        status: "ACTIVE",
        email_verified: false,
      };
      mockPrisma.$transaction.mockImplementation((callback: any) =>
        callback({
          user: { create: jest.fn().mockResolvedValue(created) },
          roleAssignment: { create: jest.fn().mockResolvedValue({}) },
        })
      );

      const result = await userService.createHotelStaff(manager, HOTEL_ID, {
        email: "hk@example.com",
        name: "HK",
        role: "HOUSEKEEPER",
      });

      expect(result.user.email).toBe("hk@example.com");
      expect(result.initial_password).toBeDefined();
    });

    it("rejects a manager creating staff in another hotel", async () => {
      await expect(
        userService.createHotelStaff(
          manager,
          "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
          { email: "x@example.com", name: "X", role: "RECEPTIONIST" }
        )
      ).rejects.toThrow(AppError);
      expect(mockPrisma.$transaction).not.toHaveBeenCalled();
    });

    it("rejects deactivating a SUPER_ADMIN assignment", async () => {
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        assignment_id: "a1",
        role: "SUPER_ADMIN",
      });

      await expect(
        userService.setHotelStaffActive(superAdmin, HOTEL_ID, "some-user", {
          is_active: false,
        })
      ).rejects.toThrow(AppError);
    });

    it("toggles a hotel assignment off", async () => {
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        assignment_id: "a1",
        role: "HOUSEKEEPER",
      });
      mockPrisma.roleAssignment.update.mockResolvedValue({ is_active: false });

      const result = await userService.setHotelStaffActive(
        superAdmin,
        HOTEL_ID,
        "some-user",
        { is_active: false }
      );

      expect(mockPrisma.roleAssignment.update).toHaveBeenCalledWith({
        where: { assignment_id: "a1" },
        data: { is_active: false },
      });
      expect(result.is_active).toBe(false);
      expect(mockPrisma.refreshSession.updateMany).toHaveBeenCalledWith({
        where: { user_id: "some-user", revoked_at: null },
        data: expect.objectContaining({ revoked_at: expect.any(Date) }),
      });
    });
  });
});

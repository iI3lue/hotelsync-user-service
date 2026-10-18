import { authService } from "../../src/services/auth.service.js";
import { AppError } from "../../src/middleware/error-handler.js";
import { hashPassword } from "../../src/lib/password.js";
import { hashRefreshToken, newRefreshToken } from "../../src/lib/tokens.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn(), create: jest.fn(), update: jest.fn() },
    roleAssignment: { create: jest.fn(), findFirst: jest.fn() },
    refreshSession: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

import prisma from "../../src/lib/prisma.js";

const mockPrisma = prisma as any;
const USER_ID = "11111111-2222-4333-8444-555555555555";
const HOTEL_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

function user(overrides = {}) {
  return {
    user_id: USER_ID,
    email: "ana@example.com",
    name: "Ana",
    phone: null,
    status: "ACTIVE",
    email_verified: false,
    terms_accepted_at: null,
    ...overrides,
  };
}

describe("AuthService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPrisma.$transaction.mockImplementation(
      (callback: (tx: unknown) => unknown) =>
        callback({
          user: { create: mockPrisma.user.create },
          roleAssignment: { create: mockPrisma.roleAssignment.create },
          refreshSession: {
            create: mockPrisma.refreshSession.create,
            update: mockPrisma.refreshSession.update,
            updateMany: mockPrisma.refreshSession.updateMany,
          },
        })
    );
    mockPrisma.refreshSession.create.mockImplementation((args: any) => ({
      session_id: "22222222-2222-4333-8444-555555555555",
      ...args.data,
    }));
  });

  describe("register", () => {
    it("creates an ACTIVE GUEST user with tokens", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      const created = user();
      mockPrisma.user.create.mockResolvedValue(created);
      mockPrisma.roleAssignment.create.mockResolvedValue({});
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        role: "GUEST",
        hotel_id: null,
      });

      const result = await authService.register({
        email: "ana@example.com",
        password: "Secret123!",
        name: "Ana",
        terms_accepted: true,
      });

      expect(result.user.email).toBe("ana@example.com");
      expect(result.access_token.split(".")).toHaveLength(3);
      expect(result.refresh_token).toHaveLength(64);
      expect(mockPrisma.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          status: "ACTIVE",
          terms_accepted_at: expect.any(Date),
        }),
      });
      expect(mockPrisma.roleAssignment.create).toHaveBeenCalledWith({
        data: { user_id: USER_ID, role: "GUEST", hotel_id: null },
      });
    });

    it("rejects a duplicate email", async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ user_id: USER_ID });

      await expect(
        authService.register({
          email: "ana@example.com",
          password: "Secret123!",
          name: "Ana",
          terms_accepted: true,
        })
      ).rejects.toThrow(AppError);
    });
  });

  describe("acceptConsent", () => {
    it("stamps terms_accepted_at on first acceptance", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(user());
      const stamped = new Date("2026-10-18T12:00:00.000Z");
      mockPrisma.user.update.mockResolvedValue(
        user({ terms_accepted_at: stamped })
      );

      const result = await authService.acceptConsent(USER_ID);

      expect(result.terms_accepted_at).toEqual(stamped);
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { user_id: USER_ID },
        data: { terms_accepted_at: expect.any(Date) },
      });
    });

    it("keeps the first acceptance (idempotent)", async () => {
      const first = new Date("2026-01-01T00:00:00.000Z");
      mockPrisma.user.findUnique.mockResolvedValue(
        user({ terms_accepted_at: first })
      );

      const result = await authService.acceptConsent(USER_ID);

      expect(result.terms_accepted_at).toEqual(first);
      expect(mockPrisma.user.update).not.toHaveBeenCalled();
    });

    it("rejects unknown or disabled accounts", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      await expect(authService.acceptConsent(USER_ID)).rejects.toThrow(
        AppError
      );

      mockPrisma.user.findUnique.mockResolvedValue(
        user({ status: "DISABLED" })
      );
      await expect(authService.acceptConsent(USER_ID)).rejects.toThrow(
        AppError
      );
    });
  });

  describe("login", () => {
    it("returns tokens for valid credentials", async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        ...user(),
        password_hash: await hashPassword("Secret123!"),
      });
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        role: "MANAGER",
        hotel_id: HOTEL_ID,
      });

      const result = await authService.login({
        email: "ana@example.com",
        password: "Secret123!",
      });

      expect(result.assignment).toMatchObject({ role: "MANAGER" });
      expect(result.access_token.split(".")).toHaveLength(3);
    });

    it("rejects wrong passwords without revealing the account", async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        ...user(),
        password_hash: await hashPassword("Secret123!"),
      });

      await expect(
        authService.login({ email: "ana@example.com", password: "wrong!" })
      ).rejects.toThrow(AppError);
    });

    it("rejects disabled accounts", async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        ...user({ status: "DISABLED" }),
        password_hash: await hashPassword("Secret123!"),
      });

      await expect(
        authService.login({ email: "ana@example.com", password: "Secret123!" })
      ).rejects.toThrow(AppError);
    });
  });

  describe("refresh/logout", () => {
    it("rotates the refresh token and revokes the old one", async () => {
      const oldToken = newRefreshToken();
      mockPrisma.refreshSession.findUnique.mockResolvedValue({
        session_id: "old-session",
        user_id: USER_ID,
        expires_at: new Date(Date.now() + 3600_000),
        revoked_at: null,
        user: user(),
      });
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        role: "GUEST",
        hotel_id: null,
      });

      mockPrisma.refreshSession.updateMany.mockResolvedValue({ count: 1 });

      const result = await authService.refresh(oldToken);

      expect(result.refresh_token).not.toBe(oldToken);
      expect(mockPrisma.refreshSession.updateMany).toHaveBeenCalledWith({
        where: { session_id: "old-session", revoked_at: null },
        data: expect.objectContaining({ revoked_at: expect.any(Date) }),
      });
    });

    it("rejects a concurrent reuse of the same refresh token", async () => {
      const oldToken = newRefreshToken();
      mockPrisma.refreshSession.findUnique.mockResolvedValue({
        session_id: "old-session",
        user_id: USER_ID,
        expires_at: new Date(Date.now() + 3600_000),
        revoked_at: null,
        user: user(),
      });
      mockPrisma.roleAssignment.findFirst.mockResolvedValue({
        role: "GUEST",
        hotel_id: null,
      });
      mockPrisma.refreshSession.updateMany.mockResolvedValue({ count: 0 });

      await expect(authService.refresh(oldToken)).rejects.toThrow(AppError);
    });

    it("rejects an unknown refresh token", async () => {
      mockPrisma.refreshSession.findUnique.mockResolvedValue(null);

      await expect(authService.refresh(newRefreshToken())).rejects.toThrow(
        AppError
      );
    });

    it("logout is idempotent", async () => {
      mockPrisma.refreshSession.updateMany.mockResolvedValue({ count: 0 });

      await expect(
        authService.logout(newRefreshToken())
      ).resolves.toEqual({ logged_out: true });
      expect(hashRefreshToken).toBeDefined();
    });
  });
});

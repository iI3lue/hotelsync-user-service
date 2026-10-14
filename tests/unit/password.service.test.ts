import { passwordService } from "../../src/services/password.service.js";
import { AppError } from "../../src/middleware/error-handler.js";
import { clearRateLimits } from "../../src/lib/rate-limit.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn() },
    passwordResetToken: { findUnique: jest.fn() },
    $transaction: jest.fn(),
  },
}));

jest.mock("../../src/lib/mailer.js", () => ({
  __esModule: true,
  sendPasswordResetEmail: jest.fn(),
}));

import prisma from "../../src/lib/prisma.js";
import { sendPasswordResetEmail } from "../../src/lib/mailer.js";

const mockPrisma = prisma as any;
const mockMailer = sendPasswordResetEmail as jest.Mock;
const USER_ID = "11111111-2222-4333-8444-555555555555";

function user(overrides = {}) {
  return {
    user_id: USER_ID,
    email: "ana@example.com",
    password_hash: "scrypt$salt$hash",
    status: "ACTIVE",
    ...overrides,
  };
}

describe("PasswordService", () => {
  let txMocks: {
    userUpdate: jest.Mock;
    prtCreate: jest.Mock;
    prtUpdate: jest.Mock;
    prtUpdateMany: jest.Mock;
    rsUpdateMany: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    clearRateLimits();
    txMocks = {
      userUpdate: jest.fn(),
      prtCreate: jest.fn(),
      prtUpdate: jest.fn(),
      prtUpdateMany: jest.fn(),
      rsUpdateMany: jest.fn(),
    };
    mockPrisma.$transaction.mockImplementation((callback: any) =>
      callback({
        user: { update: txMocks.userUpdate },
        passwordResetToken: {
          create: txMocks.prtCreate,
          update: txMocks.prtUpdate,
          updateMany: txMocks.prtUpdateMany,
        },
        refreshSession: { updateMany: txMocks.rsUpdateMany },
      })
    );
  });

  describe("requestReset", () => {
    it("returns ok without creating a token for unknown emails", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(
        passwordService.requestReset({ email: "nadie@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).not.toHaveBeenCalled();
      expect(mockMailer).not.toHaveBeenCalled();
    });

    it("returns ok without creating a token for inactive accounts", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(
        user({ status: "DISABLED" })
      );

      await expect(
        passwordService.requestReset({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).not.toHaveBeenCalled();
    });

    it("returns ok without creating a token for federated-only accounts", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(
        user({ password_hash: "federated$abc123" })
      );

      await expect(
        passwordService.requestReset({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).not.toHaveBeenCalled();
    });

    it("invalidates previous tokens and emails a reset link", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(user());

      await expect(
        passwordService.requestReset({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtUpdateMany).toHaveBeenCalledWith({
        where: { user_id: USER_ID, used_at: null },
        data: { used_at: expect.any(Date) },
      });
      expect(txMocks.prtCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          user_id: USER_ID,
          expires_at: expect.any(Date),
        }),
      });
      expect(mockMailer).toHaveBeenCalledWith(
        expect.objectContaining({ to: "ana@example.com" })
      );
    });

    it("rejects with 429 after 5 requests in the window", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      for (let i = 0; i < 5; i += 1) {
        await passwordService.requestReset({ email: "ana@example.com" });
      }
      await expect(
        passwordService.requestReset({ email: "ana@example.com" })
      ).rejects.toThrow(AppError);
    });
  });

  describe("resetPassword", () => {
    const TOKEN = "a".repeat(64);

    function record(overrides = {}) {
      return {
        token_id: "33333333-2222-4333-8444-555555555555",
        user_id: USER_ID,
        token_hash: "irrelevant-in-mock",
        expires_at: new Date(Date.now() + 3600_000),
        used_at: null,
        user: { status: "ACTIVE" },
        ...overrides,
      };
    }

    it("rotates the hash, marks the token used and revokes sessions", async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(record());

      await expect(
        passwordService.resetPassword({
          token: TOKEN,
          new_password: "NuevaClave123!",
        })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.userUpdate).toHaveBeenCalledWith({
        where: { user_id: USER_ID },
        data: { password_hash: expect.stringMatching(/^scrypt\$/) },
      });
      expect(txMocks.prtUpdate).toHaveBeenCalledWith({
        where: { token_id: record().token_id },
        data: { used_at: expect.any(Date) },
      });
      expect(txMocks.rsUpdateMany).toHaveBeenCalledWith({
        where: { user_id: USER_ID, revoked_at: null },
        data: { revoked_at: expect.any(Date) },
      });
    });

    it("rejects unknown tokens", async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(null);

      await expect(
        passwordService.resetPassword({
          token: TOKEN,
          new_password: "NuevaClave123!",
        })
      ).rejects.toThrow(AppError);
    });

    it("rejects used tokens (single use)", async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(
        record({ used_at: new Date() })
      );

      await expect(
        passwordService.resetPassword({
          token: TOKEN,
          new_password: "NuevaClave123!",
        })
      ).rejects.toThrow(AppError);
    });

    it("rejects expired tokens", async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(
        record({ expires_at: new Date(Date.now() - 1000) })
      );

      await expect(
        passwordService.resetPassword({
          token: TOKEN,
          new_password: "NuevaClave123!",
        })
      ).rejects.toThrow(AppError);
    });
  });
});

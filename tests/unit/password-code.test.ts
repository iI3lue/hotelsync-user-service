import { passwordService } from "../../src/services/password.service.js";
import { AppError } from "../../src/middleware/error-handler.js";
import { clearRateLimits } from "../../src/lib/rate-limit.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn() },
    passwordResetToken: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

import prisma from "../../src/lib/prisma.js";

const mockPrisma = prisma as any;
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

describe("PasswordService demo code", () => {
  let txMocks: {
    prtCreate: jest.Mock;
    prtUpdateMany: jest.Mock;
  };
  const prevMailer = process.env.MAILER_PROVIDER;
  const prevDemoFlag = process.env.PASSWORD_RESET_DEMO_CODE;

  beforeEach(() => {
    jest.clearAllMocks();
    clearRateLimits();
    delete process.env.MAILER_PROVIDER;
    delete process.env.PASSWORD_RESET_DEMO_CODE;
    txMocks = { prtCreate: jest.fn(), prtUpdateMany: jest.fn() };
    mockPrisma.$transaction.mockImplementation((callback: any) =>
      callback({
        passwordResetToken: {
          create: txMocks.prtCreate,
          updateMany: txMocks.prtUpdateMany,
        },
      })
    );
  });

  afterEach(() => {
    if (prevMailer === undefined) delete process.env.MAILER_PROVIDER;
    else process.env.MAILER_PROVIDER = prevMailer;
    if (prevDemoFlag === undefined) delete process.env.PASSWORD_RESET_DEMO_CODE;
    else process.env.PASSWORD_RESET_DEMO_CODE = prevDemoFlag;
  });

  describe("requestCode", () => {
    it("returns ok without a code for unknown emails", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(
        passwordService.requestCode({ email: "nadie@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).not.toHaveBeenCalled();
    });

    it("returns ok without a code for federated-only accounts", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(
        user({ password_hash: "federated$abc123" })
      );

      await expect(
        passwordService.requestCode({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).not.toHaveBeenCalled();
    });

    it("emits a 6-digit code with 10-minute expiry when the demo flag is on", async () => {
      process.env.PASSWORD_RESET_DEMO_CODE = "true";
      mockPrisma.user.findUnique.mockResolvedValue(user());
      const before = Date.now();

      const result = await passwordService.requestCode({
        email: "ana@example.com",
      });

      expect(result.ok).toBe(true);
      const code = (result as { demo_code?: string }).demo_code;
      expect(code).toMatch(/^\d{6}$/);
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
      const expiresAt = txMocks.prtCreate.mock.calls[0][0].data
        .expires_at as Date;
      expect(expiresAt.getTime()).toBeGreaterThan(before + 9 * 60_000);
      expect(expiresAt.getTime()).toBeLessThanOrEqual(before + 11 * 60_000);
    });

    it("omits the code in log mode without the demo flag (default)", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(user());

      await expect(
        passwordService.requestCode({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).toHaveBeenCalled();
    });

    it("omits the code when the mailer is smtp", async () => {
      process.env.MAILER_PROVIDER = "smtp";
      mockPrisma.user.findUnique.mockResolvedValue(user());

      await expect(
        passwordService.requestCode({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).toHaveBeenCalled();
    });

    it("omits the code when the demo flag is on but the mailer is smtp", async () => {
      process.env.MAILER_PROVIDER = "smtp";
      process.env.PASSWORD_RESET_DEMO_CODE = "true";
      mockPrisma.user.findUnique.mockResolvedValue(user());

      await expect(
        passwordService.requestCode({ email: "ana@example.com" })
      ).resolves.toEqual({ ok: true });
      expect(txMocks.prtCreate).toHaveBeenCalled();
    });

    it("rejects with 429 after 5 requests in the window", async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      for (let i = 0; i < 5; i += 1) {
        await passwordService.requestCode({ email: "ana@example.com" });
      }
      await expect(
        passwordService.requestCode({ email: "ana@example.com" })
      ).rejects.toThrow(AppError);
    });
  });

  describe("resetPassword with a demo code", () => {
    function record(overrides = {}) {
      return {
        token_id: "33333333-2222-4333-8444-555555555555",
        user_id: USER_ID,
        expires_at: new Date(Date.now() + 600_000),
        used_at: null,
        user: { status: "ACTIVE" },
        ...overrides,
      };
    }

    it("accepts a 6-digit code", async () => {
      mockPrisma.$transaction.mockImplementation((callback: any) =>
        callback({
          user: { update: jest.fn() },
          passwordResetToken: { update: jest.fn() },
          refreshSession: { updateMany: jest.fn() },
        })
      );
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(record());

      await expect(
        passwordService.resetPassword(
          { token: "482913", new_password: "NuevaClave123!" },
          "10.0.0.1"
        )
      ).resolves.toEqual({ ok: true });
    });

    it("blocks with 429 after 5 attempts from the same IP", async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue(null);
      for (let i = 0; i < 5; i += 1) {
        await expect(
          passwordService.resetPassword(
            { token: "000000", new_password: "NuevaClave123!" },
            "10.0.0.2"
          )
        ).rejects.toMatchObject({ statusCode: 400 });
      }
      await expect(
        passwordService.resetPassword(
          { token: "000000", new_password: "NuevaClave123!" },
          "10.0.0.2"
        )
      ).rejects.toMatchObject({ statusCode: 429 });
    });
  });
});

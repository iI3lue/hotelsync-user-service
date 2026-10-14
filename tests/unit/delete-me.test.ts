import { authService } from "../../src/services/auth.service.js";
import { AppError } from "../../src/middleware/error-handler.js";
import { hashPassword } from "../../src/lib/password.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn() },
    $transaction: jest.fn(),
  },
}));

jest.mock("../../src/lib/booking-client.js", () => ({
  __esModule: true,
  hasActiveBookings: jest.fn(),
}));

import prisma from "../../src/lib/prisma.js";
import { hasActiveBookings } from "../../src/lib/booking-client.js";

const mockPrisma = prisma as any;
const mockHasActive = hasActiveBookings as jest.Mock;
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

describe("AuthService.deleteMe", () => {
  let txMocks: {
    userUpdate: jest.Mock;
    rsUpdateMany: jest.Mock;
    prtUpdateMany: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    txMocks = {
      userUpdate: jest.fn(),
      rsUpdateMany: jest.fn(),
      prtUpdateMany: jest.fn(),
    };
    mockPrisma.$transaction.mockImplementation((callback: any) =>
      callback({
        user: { update: txMocks.userUpdate },
        refreshSession: { updateMany: txMocks.rsUpdateMany },
        passwordResetToken: { updateMany: txMocks.prtUpdateMany },
      })
    );
    mockHasActive.mockResolvedValue(false);
  });

  it("anonymizes the account with a valid password and no active bookings", async () => {
    const passwordHash = await hashPassword("Secret123!");
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: passwordHash })
    );

    await expect(
      authService.deleteMe(USER_ID, { password: "Secret123!" })
    ).resolves.toEqual({ ok: true });
    expect(mockHasActive).toHaveBeenCalledWith(USER_ID);
    expect(txMocks.userUpdate).toHaveBeenCalledWith({
      where: { user_id: USER_ID },
      data: expect.objectContaining({
        email: `deleted_${USER_ID}@deleted.local`,
        name: "Cuenta eliminada",
        phone: null,
        picture_url: null,
        status: "DISABLED",
        email_verified: false,
      }),
    });
    const storedHash = txMocks.userUpdate.mock.calls[0][0].data.password_hash;
    expect(storedHash).toMatch(/^deleted\$/);
    expect(txMocks.rsUpdateMany).toHaveBeenCalledWith({
      where: { user_id: USER_ID, revoked_at: null },
      data: { revoked_at: expect.any(Date) },
    });
    expect(txMocks.prtUpdateMany).toHaveBeenCalledWith({
      where: { user_id: USER_ID, used_at: null },
      data: { used_at: expect.any(Date) },
    });
  });

  it("returns 404 when the account is already deleted (retry)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ status: "DISABLED", password_hash: "deleted$abc123" })
    );

    await expect(
      authService.deleteMe(USER_ID, { password: "Secret123!" })
    ).rejects.toMatchObject({ statusCode: 404 });
    expect(mockHasActive).not.toHaveBeenCalled();
    expect(txMocks.userUpdate).not.toHaveBeenCalled();
  });

  it("rejects with 401 on wrong password without touching the DB", async () => {
    const passwordHash = await hashPassword("Secret123!");
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: passwordHash })
    );

    await expect(
      authService.deleteMe(USER_ID, { password: "Wrong123!" })
    ).rejects.toThrow(AppError);
    expect(mockHasActive).not.toHaveBeenCalled();
    expect(txMocks.userUpdate).not.toHaveBeenCalled();
  });

  it("allows federated accounts with explicit confirmation", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: "federated$abc123" })
    );

    await expect(
      authService.deleteMe(USER_ID, { confirm: true })
    ).resolves.toEqual({ ok: true });
    expect(txMocks.userUpdate).toHaveBeenCalled();
  });

  it("rejects federated accounts without confirmation", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: "federated$abc123" })
    );

    await expect(authService.deleteMe(USER_ID, {})).rejects.toThrow(AppError);
    expect(txMocks.userUpdate).not.toHaveBeenCalled();
  });

  it("blocks with 409 when there are active bookings", async () => {
    const passwordHash = await hashPassword("Secret123!");
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: passwordHash })
    );
    mockHasActive.mockResolvedValue(true);

    await expect(
      authService.deleteMe(USER_ID, { password: "Secret123!" })
    ).rejects.toThrow(AppError);
    expect(txMocks.userUpdate).not.toHaveBeenCalled();
  });

  it("fails closed with 503 when booking is unreachable", async () => {
    const passwordHash = await hashPassword("Secret123!");
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ password_hash: passwordHash })
    );
    mockHasActive.mockRejectedValue(
      new AppError(503, "Booking service unavailable", "Bad Gateway")
    );

    await expect(
      authService.deleteMe(USER_ID, { password: "Secret123!" })
    ).rejects.toThrow(AppError);
    expect(txMocks.userUpdate).not.toHaveBeenCalled();
  });
});

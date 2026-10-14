import { authService } from "../../src/services/auth.service.js";
import { AppError } from "../../src/middleware/error-handler.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn(), update: jest.fn() },
    roleAssignment: { findFirst: jest.fn() },
  },
}));

import prisma from "../../src/lib/prisma.js";

const mockPrisma = prisma as any;
const USER_ID = "11111111-2222-4333-8444-555555555555";

function user(overrides = {}) {
  return {
    user_id: USER_ID,
    email: "ana@example.com",
    name: "Ana",
    phone: null,
    picture_url: null,
    status: "ACTIVE",
    email_verified: false,
    ...overrides,
  };
}

describe("disabled accounts (post-deletion)", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPrisma.roleAssignment.findFirst.mockResolvedValue(null);
  });

  it("getMe returns 404 for DISABLED users (old JWT still signs)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(
      user({ status: "DISABLED", email: `deleted_${USER_ID}@deleted.local` })
    );

    await expect(authService.getMe(USER_ID)).rejects.toThrow(AppError);
    await expect(authService.getMe(USER_ID)).rejects.toMatchObject({
      statusCode: 404,
    });
  });

  it("getMe still works for ACTIVE users", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(user());

    const result = await authService.getMe(USER_ID);
    expect(result.user.email).toBe("ana@example.com");
  });

  it("updateMe returns 404 for DISABLED users without touching the DB", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(user({ status: "DISABLED" }));

    await expect(
      authService.updateMe(USER_ID, { name: "Otro" })
    ).rejects.toMatchObject({ statusCode: 404 });
    expect(mockPrisma.user.update).not.toHaveBeenCalled();
  });
});

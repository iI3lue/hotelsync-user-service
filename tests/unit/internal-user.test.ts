import { authService } from "../../src/services/auth.service.js";
import { requireLoyaltyKey } from "../../src/middleware/auth.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn() },
  },
}));

jest.mock("../../src/lib/booking-client.js", () => ({
  __esModule: true,
  hasActiveBookings: jest.fn(),
}));

import prisma from "../../src/lib/prisma.js";

const mockPrisma = prisma as any;
const USER_ID = "11111111-2222-4333-8444-555555555555";
const KEY = "test-loyalty-key-32-chars-min-ok!!";

describe("authService.getInternalUser", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("devuelve user_id y status sin exponer el perfil", async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      user_id: USER_ID,
      status: "ACTIVE",
    });

    await expect(authService.getInternalUser(USER_ID)).resolves.toEqual({
      user_id: USER_ID,
      status: "ACTIVE",
    });
    expect(mockPrisma.user.findUnique).toHaveBeenCalledWith({
      where: { user_id: USER_ID },
      select: { user_id: true, status: true },
    });
  });

  it("devuelve 404 si la cuenta no existe", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);

    await expect(authService.getInternalUser(USER_ID)).rejects.toMatchObject({
      statusCode: 404,
    });
  });
});

describe("requireLoyaltyKey", () => {
  const OLD = process.env.LOYALTY_SERVICE_KEY;

  beforeEach(() => {
    process.env.LOYALTY_SERVICE_KEY = KEY;
  });

  afterAll(() => {
    if (OLD === undefined) delete process.env.LOYALTY_SERVICE_KEY;
    else process.env.LOYALTY_SERVICE_KEY = OLD;
  });

  function reqWith(key?: string) {
    return {
      headers: key ? { "x-loyalty-key": key } : {},
    } as any;
  }

  it("pasa con la clave correcta", () => {
    const next = jest.fn();
    requireLoyaltyKey(reqWith(KEY), {} as any, next);
    expect(next).toHaveBeenCalledWith();
  });

  it("rechaza con 401 sin clave o con clave ajena", () => {
    for (const req of [reqWith(), reqWith("otra")]) {
      const next = jest.fn();
      requireLoyaltyKey(req, {} as any, next);
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({ statusCode: 401 })
      );
    }
  });
});

import { authService } from "../../src/services/auth.service.js";
import { AppError } from "../../src/middleware/error-handler.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn(), create: jest.fn() },
    roleAssignment: { create: jest.fn(), findFirst: jest.fn() },
    externalIdentity: { findUnique: jest.fn(), create: jest.fn() },
    refreshSession: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock("../../src/lib/federated.js", () => ({
  __esModule: true,
  verifyAuth0IdToken: jest.fn(),
}));

import prisma from "../../src/lib/prisma.js";
import { verifyAuth0IdToken } from "../../src/lib/federated.js";

const mockPrisma = prisma as any;
const mockVerify = verifyAuth0IdToken as jest.Mock;

const USER_ID = "11111111-2222-4333-8444-555555555555";

function user(overrides = {}) {
  return {
    user_id: USER_ID,
    email: "google.user@example.com",
    name: "Google User",
    phone: null,
    status: "ACTIVE",
    email_verified: true,
    ...overrides,
  };
}

describe("AuthService.federated", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerify.mockResolvedValue({
      sub: "google-oauth2|123456",
      email: "google.user@example.com",
      emailVerified: true,
      name: "Google User",
    });
    mockPrisma.$transaction.mockImplementation(
      (callback: (tx: unknown) => unknown) =>
        callback({
          user: { create: mockPrisma.user.create },
          roleAssignment: { create: mockPrisma.roleAssignment.create },
          externalIdentity: { create: mockPrisma.externalIdentity.create },
        })
    );
    mockPrisma.refreshSession.create.mockImplementation((args: any) => ({
      session_id: "22222222-2222-4333-8444-555555555555",
      ...args.data,
    }));
  });

  it("creates a GUEST account on first federated login", async () => {
    mockPrisma.externalIdentity.findUnique.mockResolvedValue(null);
    mockPrisma.user.findUnique.mockResolvedValue(null);
    const created = user();
    mockPrisma.user.create.mockResolvedValue(created);
    mockPrisma.roleAssignment.findFirst.mockResolvedValue({
      role: "GUEST",
      hotel_id: null,
    });

    const result = await authService.federated({
      provider: "auth0",
      id_token: "valid-id-token",
      nonce: "oauth-nonce",
    });

    expect(mockVerify).toHaveBeenCalledWith("valid-id-token", "oauth-nonce");
    expect(mockPrisma.externalIdentity.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        provider: "auth0",
        provider_sub: "google-oauth2|123456",
      }),
    });
    expect(result.access_token.split(".")).toHaveLength(3);
    expect(result.user.email_verified).toBe(true);
  });

  it("reuses the linked account on subsequent logins", async () => {
    const existing = user();
    mockPrisma.externalIdentity.findUnique.mockResolvedValue({
      provider: "auth0",
      provider_sub: "google-oauth2|123456",
      user_id: USER_ID,
      user: existing,
    });
    mockPrisma.roleAssignment.findFirst.mockResolvedValue({
      role: "GUEST",
      hotel_id: null,
    });

    const result = await authService.federated({
      provider: "auth0",
      id_token: "valid-id-token",
      nonce: "oauth-nonce",
    });

    expect(mockPrisma.user.create).not.toHaveBeenCalled();
    expect(result.user.user_id).toBe(USER_ID);
  });

  it("rejects email takeover of a password account", async () => {
    mockPrisma.externalIdentity.findUnique.mockResolvedValue(null);
    mockPrisma.user.findUnique.mockResolvedValue({ user_id: USER_ID });

    await expect(
      authService.federated({
        provider: "auth0",
        id_token: "valid-id-token",
        nonce: "oauth-nonce",
      })
    ).rejects.toThrow(AppError);
    expect(mockPrisma.user.create).not.toHaveBeenCalled();
  });

  it("rejects identities without email", async () => {
    mockVerify.mockResolvedValue({ sub: "google-oauth2|999" });

    await expect(
      authService.federated({
        provider: "auth0",
        id_token: "valid-id-token",
        nonce: "oauth-nonce",
      })
    ).rejects.toThrow(AppError);
  });
});

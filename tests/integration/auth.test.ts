import request from "supertest";
import express from "express";
import authRouter from "../../src/routes/auth.js";
import usersRouter from "../../src/routes/users.js";
import { errorHandler } from "../../src/middleware/error-handler.js";
import { hashPassword } from "../../src/lib/password.js";
import { signAccessToken } from "../../src/lib/tokens.js";

jest.mock("../../src/lib/prisma.js", () => ({
  __esModule: true,
  default: {
    user: { findUnique: jest.fn(), create: jest.fn(), update: jest.fn() },
    roleAssignment: { findFirst: jest.fn(), create: jest.fn() },
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
const PASSWORD = "Secret1234";

const tx = {
  user: { create: jest.fn() },
  roleAssignment: { create: jest.fn() },
};

const app = express();
app.use(express.json());
app.use("/v1/auth", authRouter);
app.use("/v1/users", usersRouter);
app.use(errorHandler);

function user(overrides: Record<string, unknown> = {}) {
  return {
    user_id: USER_ID,
    email: "ana@example.com",
    name: "Ana",
    phone: null,
    picture_url: null,
    status: "ACTIVE",
    email_verified: false,
    terms_accepted_at: new Date("2026-01-01T00:00:00Z"),
    ...overrides,
  };
}

const GUEST_ASSIGNMENT = { user_id: USER_ID, role: "GUEST", hotel_id: null };
const STAFF_ASSIGNMENT = {
  user_id: USER_ID,
  role: "RECEPTIONIST",
  hotel_id: HOTEL_ID,
};

const staffToken = () =>
  signAccessToken({
    sub: USER_ID,
    email: "ana@example.com",
    role: "RECEPTIONIST",
    hotel_id: HOTEL_ID,
  });

let passwordHash: string;

beforeAll(async () => {
  passwordHash = await hashPassword(PASSWORD);
});

beforeEach(() => {
  jest.clearAllMocks();
  mockPrisma.$transaction.mockImplementation((cb: any) => cb(tx));
  mockPrisma.refreshSession.create.mockResolvedValue({ session_id: "s-1" });
});

describe("POST /v1/auth/register", () => {
  const body = {
    email: "ana@example.com",
    password: PASSWORD,
    name: "Ana",
    terms_accepted: true,
  };

  it("rechaza el alta sin aceptar los términos (400)", async () => {
    const res = await request(app)
      .post("/v1/auth/register")
      .send({ ...body, terms_accepted: undefined });
    expect(res.status).toBe(400);
    expect(mockPrisma.user.findUnique).not.toHaveBeenCalled();
  });

  it("rechaza un email ya registrado (409)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ user_id: "otro" });
    const res = await request(app).post("/v1/auth/register").send(body);
    expect(res.status).toBe(409);
    expect(tx.user.create).not.toHaveBeenCalled();
  });

  it("crea la cuenta GUEST y devuelve la sesión (201)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);
    tx.user.create.mockResolvedValue(user());
    tx.roleAssignment.create.mockResolvedValue({});
    mockPrisma.roleAssignment.findFirst.mockResolvedValue(GUEST_ASSIGNMENT);

    const res = await request(app).post("/v1/auth/register").send(body);

    expect(res.status).toBe(201);
    expect(res.body.access_token).toEqual(expect.any(String));
    expect(res.body.refresh_token).toEqual(expect.any(String));
    expect(res.body.user.email).toBe("ana@example.com");
    expect(tx.roleAssignment.create).toHaveBeenCalledWith({
      data: { user_id: USER_ID, role: "GUEST", hotel_id: null },
    });
    expect(mockPrisma.refreshSession.create).toHaveBeenCalledTimes(1);
  });
});

describe("POST /v1/auth/login", () => {
  it("rechaza credenciales inválidas (401)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      ...user(),
      password_hash: passwordHash,
    });
    const res = await request(app)
      .post("/v1/auth/login")
      .send({ email: "ana@example.com", password: "wrong-password" });
    expect(res.status).toBe(401);
    expect(mockPrisma.refreshSession.create).not.toHaveBeenCalled();
  });

  it("rechaza una cuenta sin rol activo (403)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      ...user(),
      password_hash: passwordHash,
    });
    mockPrisma.roleAssignment.findFirst.mockResolvedValue(null);
    const res = await request(app)
      .post("/v1/auth/login")
      .send({ email: "ana@example.com", password: PASSWORD });
    expect(res.status).toBe(403);
  });

  it("emite la sesión con el rol asignado (200)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue({
      ...user(),
      password_hash: passwordHash,
    });
    mockPrisma.roleAssignment.findFirst.mockResolvedValue(STAFF_ASSIGNMENT);

    const res = await request(app)
      .post("/v1/auth/login")
      .send({ email: "ana@example.com", password: PASSWORD });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toEqual(expect.any(String));
    expect(res.body.assignment.role).toBe("RECEPTIONIST");
    expect(mockPrisma.refreshSession.create).toHaveBeenCalledTimes(1);
  });
});

describe("GET /v1/users/me", () => {
  it("rechaza sin token (401)", async () => {
    const res = await request(app).get("/v1/users/me");
    expect(res.status).toBe(401);
    expect(mockPrisma.user.findUnique).not.toHaveBeenCalled();
  });

  it("devuelve el perfil con su rol (200)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(user());
    mockPrisma.roleAssignment.findFirst.mockResolvedValue(STAFF_ASSIGNMENT);

    const res = await request(app)
      .get("/v1/users/me")
      .set("Authorization", `Bearer ${staffToken()}`);

    expect(res.status).toBe(200);
    expect(res.body.user.user_id).toBe(USER_ID);
    expect(res.body.assignment.role).toBe("RECEPTIONIST");
  });

  it("devuelve 404 si la cuenta ya no existe (200 lógico)", async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);
    const res = await request(app)
      .get("/v1/users/me")
      .set("Authorization", `Bearer ${staffToken()}`);
    expect(res.status).toBe(404);
  });
});

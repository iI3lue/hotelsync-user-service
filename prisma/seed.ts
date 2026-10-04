import { randomBytes, scrypt as scryptCallback } from "node:crypto";
import { promisify } from "node:util";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const scrypt = promisify(scryptCallback);

/** Duplicado local de src/lib/password.ts: el seed corre con tsx fuera de src. */
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const derived = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt$${salt}$${derived.toString("hex")}`;
}

async function main() {
  console.log("Seeding user database...");

  const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!email || !password) {
    console.log("BOOTSTRAP_ADMIN_EMAIL/PASSWORD not set, skipping admin seed.");
    return;
  }

  const existing = await prisma.user.findUnique({
    where: { email },
    select: { user_id: true },
  });
  if (existing) {
    console.log(`Admin ${email} already exists, skipping.`);
    return;
  }

  await prisma.$transaction(async (tx) => {
    const admin = await tx.user.create({
      data: {
        email,
        password_hash: await hashPassword(password),
        name: "HotelSync Admin",
        status: "ACTIVE",
      },
    });
    await tx.roleAssignment.create({
      data: { user_id: admin.user_id, role: "SUPER_ADMIN", hotel_id: null },
    });
  });

  console.log(`Bootstrap SUPER_ADMIN ${email} created.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

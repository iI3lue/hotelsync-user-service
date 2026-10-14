import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
import { requireAuth, requireLoyaltyKey } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import {
  deleteMeSchema,
  updateMeSchema,
  userIdParamSchema,
} from "../validators/auth.js";

const router = Router();

router.get("/me", requireAuth, authController.me.bind(authController));
router.patch(
  "/me",
  requireAuth,
  validate(updateMeSchema),
  authController.updateMe.bind(authController)
);
router.delete(
  "/me",
  requireAuth,
  validate(deleteMeSchema),
  authController.deleteMe.bind(authController)
);
// Interno servidor-a-servidor (loyalty-service, earn): sin JWT de usuario.
router.get(
  "/internal/:id",
  requireLoyaltyKey,
  validate(userIdParamSchema, "params"),
  authController.getInternalUser.bind(authController)
);

export default router;

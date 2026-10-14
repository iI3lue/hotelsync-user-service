import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
import { validate } from "../middleware/validate.js";
import {
  federatedSchema,
  forgotPasswordSchema,
  loginSchema,
  logoutSchema,
  refreshSchema,
  registerSchema,
  requestCodeSchema,
  resetPasswordSchema,
} from "../validators/auth.js";

const router = Router();

router.post("/register", validate(registerSchema), authController.register.bind(authController));
router.post("/password/forgot", validate(forgotPasswordSchema), authController.forgotPassword.bind(authController));
router.post("/password/reset", validate(resetPasswordSchema), authController.resetPassword.bind(authController));
router.post("/password/code", validate(requestCodeSchema), authController.requestCode.bind(authController));
router.post("/federated", validate(federatedSchema), authController.federated.bind(authController));
router.post("/login", validate(loginSchema), authController.login.bind(authController));
router.post("/refresh", validate(refreshSchema), authController.refresh.bind(authController));
router.post("/logout", validate(logoutSchema), authController.logout.bind(authController));

export default router;

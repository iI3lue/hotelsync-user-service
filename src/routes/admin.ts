import { Router } from "express";
import { userController } from "../controllers/user.controller.js";
import { requireAuth, requireSuperAdmin } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import {
  createStaffSchema,
  listStaffQuerySchema,
  updateStaffSchema,
  userIdParamSchema,
} from "../validators/auth.js";

const router = Router();

router.use(requireAuth);

router.post(
  "/users",
  requireSuperAdmin,
  validate(createStaffSchema),
  userController.createStaff.bind(userController)
);
router.get(
  "/users",
  validate(listStaffQuerySchema, "query"),
  userController.listStaff.bind(userController)
);
router.patch(
  "/users/:id",
  requireSuperAdmin,
  validate(userIdParamSchema, "params"),
  validate(updateStaffSchema),
  userController.updateStaff.bind(userController)
);

export default router;

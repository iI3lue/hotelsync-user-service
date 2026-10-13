import { Router } from "express";
import { userController } from "../controllers/user.controller.js";
import { requireAuth } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import {
  createHotelStaffSchema,
  createStaffSchema,
  hotelIdParamSchema,
  hotelStaffIdParamSchema,
  listStaffQuerySchema,
  setHotelStaffActiveSchema,
  updateStaffSchema,
  userIdParamSchema,
} from "../validators/auth.js";

const router = Router();

router.use(requireAuth);

// Gestión global de personal (solo SUPER_ADMIN)
router.post(
  "/staff",
  validate(createStaffSchema),
  userController.createStaff.bind(userController)
);
router.get(
  "/staff",
  validate(listStaffQuerySchema, "query"),
  userController.listStaff.bind(userController)
);
router.patch(
  "/staff/:id",
  validate(userIdParamSchema, "params"),
  validate(updateStaffSchema),
  userController.updateStaff.bind(userController)
);

// Personal de un hotel: SUPER_ADMIN en cualquiera, MANAGER solo en el suyo.
router.post(
  "/hotels/:hotelId/staff",
  validate(hotelIdParamSchema, "params"),
  validate(createHotelStaffSchema),
  userController.createHotelStaff.bind(userController)
);
router.get(
  "/hotels/:hotelId/staff",
  validate(hotelIdParamSchema, "params"),
  validate(listStaffQuerySchema, "query"),
  userController.listHotelStaff.bind(userController)
);
router.patch(
  "/hotels/:hotelId/staff/:userId",
  validate(hotelStaffIdParamSchema, "params"),
  validate(setHotelStaffActiveSchema),
  userController.setHotelStaffActive.bind(userController)
);

export default router;

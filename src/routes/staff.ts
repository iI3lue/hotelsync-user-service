import { Router } from "express";
import { userController } from "../controllers/user.controller.js";
import { requireAuth } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import {
  createHotelStaffSchema,
  hotelIdParamSchema,
  hotelStaffIdParamSchema,
  listStaffQuerySchema,
  setHotelStaffActiveSchema,
} from "../validators/auth.js";

const router = Router();

router.use(requireAuth);

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

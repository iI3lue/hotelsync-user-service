import { Request, Response, NextFunction } from "express";
import { userService } from "../services/user.service.js";
import { AuthRequest } from "../middleware/auth.js";

export class UserController {
  async createStaff(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.createStaff(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.body
      );
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }

  async listStaff(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.listStaff(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.query as never
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  }

  async updateStaff(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.updateStaff(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.params.id as string,
        req.body
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  }

  async createHotelStaff(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.createHotelStaff(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.params.hotelId as string,
        req.body
      );
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }

  async listHotelStaff(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.listHotelStaff(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.params.hotelId as string,
        (req.query as { role?: string }).role
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  }

  async setHotelStaffActive(req: Request, res: Response, next: NextFunction) {
    try {
      const auth = (req as AuthRequest).auth;
      const result = await userService.setHotelStaffActive(
        auth ?? { sub: "", email: "", role: "", hotel_id: null, scope: "global", iss: "", aud: "", email_verified: false, iat: 0, exp: 0 },
        req.params.hotelId as string,
        req.params.userId as string,
        req.body
      );
      res.json(result);
    } catch (err) {
      next(err);
    }
  }
}

export const userController = new UserController();

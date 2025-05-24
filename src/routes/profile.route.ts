import express, { NextFunction, Request, Response } from "express";
import { verifyToken } from "../middlewares/profile.middleware";
import { profile } from "../controllers/profile.controller";

const router = express.Router();

router.get(
  '/',
  (req: Request, res: Response, next: NextFunction) => {
    verifyToken(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    profile(req, res).catch(next);
  }
);

export default router;
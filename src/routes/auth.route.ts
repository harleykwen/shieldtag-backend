import express, { NextFunction, Request, Response } from 'express';
import { login, register } from '../controllers/auth.controller';
import { loginValidator, registerValidator, validateRequest } from '../middlewares/auth.middleware';

const router = express.Router();

router.post(
  '/register',
  registerValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    register(req, res).catch(next);
  }
);

router.post(
  '/login',
  loginValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    login(req, res).catch(next);
  }
);

export default router;

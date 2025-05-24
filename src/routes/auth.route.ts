import express, { NextFunction, Request, Response } from 'express';
import { login, loginVerifyOtp, register, resendOtp } from '../controllers/auth.controller';
import { loginValidator, loginVerifyOtpValidator, registerValidator, resendOtpValidator, validateRequest } from '../middlewares/auth.middleware';

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

router.post(
  '/login/verify',
  loginVerifyOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    loginVerifyOtp(req, res).catch(next);
  }
);

router.post(
  '/resend-otp',
  resendOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    resendOtp(req, res).catch(next);
  }
);

export default router;

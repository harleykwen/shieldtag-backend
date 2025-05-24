import express, { NextFunction, Request, Response } from 'express';
import { login, loginVerifyOtp, register, registerResendOtp, registerVerifyOtp, loginResendOtp, forgotPasswordRequestOtp, forgotPasswordVerifyOtp, forgotPasswordReset, forgotPasswordResendOtp } from '../controllers/auth.controller';
import { loginValidator, loginVerifyOtpValidator, registerValidator, registerVerifyOtpValidator, loginResendOtpValidator, validateRequest, registerResendOtpValidator, forgotPasswordRequestOtpValidator, forgotPasswordVerifyOtpValidator, forgotPasswordResetValidator, forgotPasswordResendOtpValidator } from '../middlewares/auth.middleware';

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
  '/register/verify',
  registerVerifyOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    registerVerifyOtp(req, res).catch(next);
  }
);

router.post(
  '/register/resend-otp',
  registerResendOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    registerResendOtp(req, res).catch(next);
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
  '/login/resend-otp',
  loginResendOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    loginResendOtp(req, res).catch(next);
  }
);

router.post(
  '/forgot-password',
  forgotPasswordRequestOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    forgotPasswordRequestOtp(req, res).catch(next);
  }
);

router.post(
  '/forgot-password/verify',
  forgotPasswordVerifyOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    forgotPasswordVerifyOtp(req, res).catch(next);
  }
);

router.post(
  '/forgot-password/resend-otp',
  forgotPasswordResendOtpValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    forgotPasswordResendOtp(req, res).catch(next);
  }
);

router.post(
  '/forgot-password/reset',
  forgotPasswordResetValidator,
  (req: Request, res: Response, next: NextFunction) => {
    validateRequest(req, res, next)
  },
  (req: Request, res: Response, next: NextFunction) => {
    forgotPasswordReset(req, res).catch(next);
  }
);

export default router;

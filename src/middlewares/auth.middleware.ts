import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const registerValidator = [
  body('email').isEmail().withMessage('Email must be valid'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

export const registerVerifyOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
  body('otp')
    .notEmpty()
    .withMessage('OTP is required')
    .isLength({ max: 6, min: 6 })
    .withMessage('otp must be exactly 6 digits long')
];

export const registerResendOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
];

export const loginValidator = [
  body('email').isEmail().withMessage('Email must be valid'),
  body('password').notEmpty().withMessage('Password is required'),
];

export const loginVerifyOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
  body('otp')
    .notEmpty()
    .withMessage('otp is required')
    .isLength({ max: 6, min: 6 })
    .withMessage('OTP must be exactly 6 digits long')
];

export const loginResendOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
];

export const forgotPasswordRequestOtpValidator = [
  body('email').isEmail().withMessage('Email must be valid'),
];

export const forgotPasswordVerifyOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
  body('otp')
    .notEmpty()
    .withMessage('OTP is required')
    .isLength({ max: 6, min: 6 })
    .withMessage('otp must be exactly 6 digits long')
];

export const forgotPasswordResendOtpValidator = [
  body('otp_id').notEmpty().withMessage('ID OTP is required'),
];

export const forgotPasswordResetValidator = [
  body('token').notEmpty().withMessage('ID OTP is required'),
  body('password').notEmpty().withMessage('Password is required'),
];

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: true,
      message: errors.array()[0].msg
    });
  }
  next();
};
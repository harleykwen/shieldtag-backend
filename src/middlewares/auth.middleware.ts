import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const registerValidator = [
  body('email').isEmail().withMessage('Must be a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

export const registerVerifyOtpValidator = [
  body('otp_id').notEmpty().withMessage('otp_id is required'),
  body('otp')
    .notEmpty()
    .withMessage('otp is required')
    .isLength({ max: 6, min: 6 })
    .withMessage('otp must be exactly 6 digits long')
];

export const registerResendOtpValidator = [
  body('otp_id').notEmpty().withMessage('otp_id is required'),
];

export const loginValidator = [
  body('email').isEmail().withMessage('Must be a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
];

export const loginVerifyOtpValidator = [
  body('otp_id').notEmpty().withMessage('otp_id is required'),
  body('otp')
    .notEmpty()
    .withMessage('otp is required')
    .isLength({ max: 6, min: 6 })
    .withMessage('otp must be exactly 6 digits long')
];

export const loginResendOtpValidator = [
  body('otp_id').notEmpty().withMessage('otp_id is required'),
];

export const validateRequest = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};
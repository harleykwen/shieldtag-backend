import { Request, Response } from 'express';
import User from '../models/User.model';
import RegistrationModel from '../models/Registration.model'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import OtpModel from '../models/Otp.model';
import { sendMail } from '../utils/mail.util';
import { generateOTP } from '../utils/otp.util';

const JWT_SECRET = process.env.JWT_SECRET as string;

export async function register(req: Request, res: Response): Promise<Response> {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({
      error: true,
      message: 'User already exists'
    });

    const code = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const createOtp = await OtpModel.create({ email, code, type: 'register', expiresAt })

    const hashedPassword = await bcrypt.hash(password, 10);
    const newRegistration = new RegistrationModel({ email, password: hashedPassword, otp_id: createOtp._id });
    await newRegistration.save();

    await sendMail(email, 'Your Registration OTP', `Your OTP is ${code}`);

    return res.status(200).json({
      error: false,
      message: "We've sent an One-Time Password (OTP) to your email address. Please check your inbox (and spam folder, just in case) to retrieve the OTP and complete your registration.",
      data: {
        otp_id: createOtp._id
      }
    });
  } catch (err) {
    console.log(err)
    return res.status(500).json({ error: 'Server error' });
  }
};

export async function registerVerifyOtp(req: Request, res: Response): Promise<Response> {
  const { otp, otp_id } = req.body;

  try {
    const record = await OtpModel.findOne({ _id: otp_id, code: otp, type: 'register' });
    if (!record || record.expiresAt < new Date()) return res.status(400).json({
      error: true,
      message: 'Invalid or expired OTP'
    });

    const registration = await RegistrationModel.findOne({ otp_id: record._id });
    if (!registration) return res.status(400).json({
      error: true,
      message: 'Your registration session is invalid. Please create new registration to continue'
    });

    const isExist = await User.findOne({ email: registration.email });
    if (isExist) return res.status(404).json({
      error: true,
      message: 'Email already registered'
    });

    const newUser = new User({ email: registration.email, password: registration.password });
    await newUser.save();
    await RegistrationModel.deleteMany({ email: record.email });
    await OtpModel.deleteMany({ email: record.email, type: 'register' });

    return res.status(200).json({
      error: false,
      message: "Registration successful",
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};

export async function registerResendOtp(req: Request, res: Response): Promise<Response> {
  const { otp_id } = req.body;

  try {
    const record = await OtpModel.findOne({ _id: otp_id });
    if (!record) return res.status(400).json({
      error: true,
      message: "Your OTP session has invalid. Please request a new register session to continue."
    });
    if (record.expiresAt > new Date()) return res.status(400).json({
      error: true,
      message: "Your OTP session is valid. You may proceed with verification."
    });

    const code = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const createOtp = await OtpModel.create({ email: record.email, code, type: record.type, expiresAt })
    await RegistrationModel.findOneAndUpdate(
      { email: 'harleykwen.work2@gmail.com' },
      { $set: { otp_id: createOtp._id } },
    );

    return res.status(200).json({
      error: false,
      message: "We've sent an One-Time Password (OTP) to your registered email address. Please check your inbox (and spam folder, just in case) to retrieve the OTP and complete your login.",
      data: {
        otp_id: createOtp._id
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};

export async function login(req: Request, res: Response): Promise<Response> {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({
      error: true,
      message: 'Invalid credentials'
    });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({
      error: true,
      message: 'Invalid credentials'
    });

    const code = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const createOtp = await OtpModel.create({ email, code, type: 'login', expiresAt })
    await sendMail(email, 'Your Login OTP', `Your OTP is ${code}`);

    return res.status(200).json({
      error: false,
      message: "We've sent an One-Time Password (OTP) to your registered email address. Please check your inbox (and spam folder, just in case) to retrieve the OTP and complete your login.",
      data: {
        otp_id: createOtp._id
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};

export async function loginVerifyOtp(req: Request, res: Response): Promise<Response> {
  const { otp, otp_id } = req.body;

  try {
    const record = await OtpModel.findOne({ _id: otp_id, code: otp, type: 'login' });
    if (!record || record.expiresAt < new Date()) return res.status(400).json({
      error: true,
      message: 'Invalid or expired OTP'
    });

    const user = await User.findOne({ email: record.email });
    if (!user) return res.status(404).json({
      error: true,
      message: 'User not found'
    });
    await OtpModel.deleteMany({ email: record.email, type: 'login' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    return res.status(200).json({
      error: false,
      message: "Login successful",
      data: { token },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};

export async function loginResendOtp(req: Request, res: Response): Promise<Response> {
  const { otp_id } = req.body;

  try {
    const record = await OtpModel.findOne({ _id: otp_id });
    if (!record) return res.status(400).json({
      error: true,
      message: "Your OTP session has invalid. Please request a new login session to continue."
    });
    if (record.expiresAt > new Date()) return res.status(400).json({
      error: true,
      message: "Your OTP session is valid. You may proceed with verification."
    });

    const code = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const createOtp = await OtpModel.create({ email: record.email, code, type: record.type, expiresAt })

    return res.status(200).json({
      error: false,
      message: "We've sent an One-Time Password (OTP) to your registered email address. Please check your inbox (and spam folder, just in case) to retrieve the OTP and complete your login.",
      data: {
        otp_id: createOtp._id
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
};

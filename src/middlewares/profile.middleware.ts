import { NextFunction, Request, Response } from "express";
import jwt, { JsonWebTokenError, JwtPayload, TokenExpiredError } from 'jsonwebtoken';
import UserModel from "../models/User.model";

export interface IAuthenticatedRequest extends Request {
  user?: any
}

const JWT_SECRET = process.env.JWT_SECRET as string;

export async function verifyToken(
  req: IAuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: true,
      message: 'You are unauthorized'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = (decoded as JwtPayload & { userId: string }).userId;

    const user = await UserModel.findOne({ _id: userId }).select('-password -_id -__v');

    req.user = user; // attach user info to request
    next(); // move to next middleware or route
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      return res.status(401).json({ message: 'Token has expired' });
    }

    if (err instanceof JsonWebTokenError) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    return res.status(500).json({ message: 'Internal server error' });
  }
};
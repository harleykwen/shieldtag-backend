import { Request, Response } from "express";
import { IAuthenticatedRequest } from "../middlewares/profile.middleware";

export async function profile(req: IAuthenticatedRequest, res: Response): Promise<Response> {
  return res.status(200).json({ data: req.user })
};
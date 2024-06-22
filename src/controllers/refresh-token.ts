import { getUserByUsername, signToken } from '@auth/services/auth.service';
import { IAuthDocument } from '@k0msak007/jobber-shared';
import { NextFunction, Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';

export async function token(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const existingUser: IAuthDocument | undefined = await getUserByUsername(req.params.username);
    const userJWT: string = signToken(existingUser!.id!, existingUser!.email!, existingUser!.username!);
    res.status(StatusCodes.OK).json({ message: 'Refresh token', user: existingUser, token: userJWT });
  } catch (error) {
    next(error);
  }
}

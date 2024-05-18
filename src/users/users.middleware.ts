import {
  HttpException,
  HttpStatus,
  Injectable,
  NestMiddleware,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Injectable()
export class UsersMiddleware implements NestMiddleware {
  use(req: any, res: Response, next: () => void) {
    // console.log('req.headers.authorization', req.headers.authorization);

    // if (
    //   !req.headers.authorization ||
    //   req.headers.authorization.split(' ')[1] !== 'token-secret'
    // ) {
    //   throw new HttpException('Token invalid', HttpStatus.FORBIDDEN);
    // }
    next();
  }
}

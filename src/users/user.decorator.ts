import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { ERole } from 'src/auth/auth.enum';

export const UserRequest = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);

export interface IUserRequest {
  id: number;
  role: ERole;
}

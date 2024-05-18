import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  Res,
  ParseIntPipe,
  UseGuards,
} from '@nestjs/common';
import { CreateUserDto } from './CreateUser.dto';
import { AuthGuard } from './guard/auth/auth.guard';
import { ValidateCreateUserPipe } from './pipe/validate-create-user/validate-create-user.pipe';
import { UsersService } from './users.service';

@Controller('users')
@UseGuards(AuthGuard)
export class UsersController {
  constructor(private usersService: UsersService) {}

  // @Get()
  // getUsers() {
  //   return this.usersService.getUsers();
  // }
  // @Post()
  // createUser(@Body(ValidateCreateUserPipe) userData: CreateUserDto) {
  //   return this.usersService.createUser(userData);
  // }
  // @Get(':id')
  // getUserById(@Param('id', ParseIntPipe) id) {
  //   return this.usersService.getUserById(id);
  // }
}

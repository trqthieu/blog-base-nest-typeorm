import {
  Controller,
  Get,
  Request,
  Post,
  UseGuards,
  Session,
  Body,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { SignupDto } from './dtos/signup.dto';
import { Public } from './auth.decorator';

@Controller('auth')
@ApiTags('auth')
@ApiBearerAuth()
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return await this.authService.login(loginDto);
  }

  @Public()
  @Post('signup')
  async signup(@Body() signupDto: SignupDto) {
    return await this.authService.signup(signupDto);
  }

  @Get('get-users')
  async getUser() {
    return await this.authService.getUser();
  }

  // @Get()
  // async getAuthSession(@Session() session: Record<string, any>) {
  //   session.visits = session.visits ? session.visits + 1 : 1;
  //   console.log('session', session);
  //   return session;
  // }
}

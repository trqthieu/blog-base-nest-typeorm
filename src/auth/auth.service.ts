import { BadRequestException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dtos/login.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/typeorm/User.entity';
import { Repository } from 'typeorm';
import { comparePassword, hashPassword } from 'src/utils/bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dtos/signup.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto) {
    const user = await this.userRepository.findOne({
      where: {
        email: loginDto.email,
      },
    });
    if (!user) {
      throw new BadRequestException('User not found');
    }
    if (!comparePassword(loginDto.password, user.password)) {
      throw new BadRequestException('Password is not match');
    }
    const access_token = this.jwtService.sign({
      id: user.id,
      role: user.role,
    });
    return { access_token };
  }

  async signup(signupDto: SignupDto) {
    const { email, description, fullName, username, password } = signupDto;
    const user = await this.userRepository.findOne({
      where: {
        email: signupDto.email,
      },
    });
    if (user) {
      throw new BadRequestException('User has been existed');
    }
    const hash = hashPassword(password);
    const newUser = new User();
    newUser.email = email;
    newUser.username = username;
    newUser.fullName = fullName;
    newUser.description = description;
    newUser.password = hash;
    return await this.userRepository.save(newUser);
  }

  // async validateUser(username: string, pass: string): Promise<any> {
  //   const user = await this.usersService.findOne(username);
  //   if (user && user.password === pass) {
  //     const { password, ...result } = user;
  //     return result;
  //   }
  //   return null;
  // }
}

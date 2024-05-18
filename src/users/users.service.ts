import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './CreateUser.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/typeorm/User.entity';
import { HttpException } from '@nestjs/common/exceptions';
import { HttpStatus } from '@nestjs/common/enums';
@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
  ) {}
  getUsers() {
    return this.usersRepository.find();
  }
  async createUser(userData: CreateUserDto) {
    const user = await this.usersRepository.findOneBy({
      email: userData.email,
    });
    if (user) {
      throw new HttpException(
        'Email has already exist!',
        HttpStatus.BAD_REQUEST,
      );
    }
    // const password = await encodePassword(userData.password);
    // const newUser = this.usersRepository.create({ ...userData, password });
    const newUser = this.usersRepository.create(userData);
    return this.usersRepository.save(newUser);
  }
  getUserById(id: number) {
    return this.usersRepository.findOneBy({ id });
  }
  async findOne(id: number) {
    return await this.usersRepository.findOne({ where: { id } });
  }
}

/* eslint-disable prettier/prettier */
import { IsNotEmpty, IsEmail, IsNumber, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @MinLength(8)
  name: string;
  @IsEmail()
  email: string;
  //   @IsNumber()
  age: number;
  @IsNotEmpty()
  @MinLength(6)
  password: string;
}

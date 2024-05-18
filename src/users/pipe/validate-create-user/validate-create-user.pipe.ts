import { ArgumentMetadata, Injectable, PipeTransform } from '@nestjs/common';
import { HttpStatus } from '@nestjs/common/enums';
import { HttpException } from '@nestjs/common/exceptions';
import { CreateUserDto } from 'src/users/CreateUser.dto';

@Injectable()
export class ValidateCreateUserPipe implements PipeTransform {
  transform(value: CreateUserDto, metadata: ArgumentMetadata) {
    console.log('value', value);
    console.log('metadata', metadata);
    const ageInt = parseInt(value.age.toString());
    if (isNaN(ageInt)) {
      console.log(`${value.age} is not a number`);
      throw new HttpException(
        'Invalid type for age property',
        HttpStatus.BAD_REQUEST,
      );
    }
    console.log(`${value.age} is a number`);
    return { ...value, age: ageInt };
  }
}

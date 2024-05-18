import { ApiProperty } from '@nestjs/swagger';
import { IsInt, IsString } from 'class-validator';

export class CreatePostDto {
  @ApiProperty()
  @IsString()
  title: string;

  @ApiProperty()
  @IsString()
  coverImage: string;

  @ApiProperty()
  @IsInt()
  categoryId: number;

  @ApiProperty()
  @IsString()
  content: string;
}

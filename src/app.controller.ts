import {
  ArgumentMetadata,
  BadRequestException,
  Body,
  Controller,
  Get,
  Injectable,
  Param,
  ParseFilePipeBuilder,
  PipeTransform,
  Post,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { AppService } from './app.service';
import { Public } from './auth/auth.decorator';
import { ApiConsumes } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { ApiProperty } from '@nestjs/swagger';

@Injectable()
export class ImageFileValidationPipe implements PipeTransform {
  transform(file: Express.Multer.File, metadata: ArgumentMetadata) {
    if (!file?.originalname.match(/\.(jpg|jpeg|png|webp)$/)) {
      throw new BadRequestException('Invalid file type');
    }
    const maxFileSizeInBytes = 10 * 1024 * 1024; // 10MB
    if (file.size > maxFileSizeInBytes) {
      throw new BadRequestException(
        'File size exceeds the maximum allowed (10MB)',
      );
    }
    return file;
  }
}

export class FileDto {
  @ApiProperty({ type: 'string', format: 'binary' })
  file: Express.Multer.File;
}

@Controller('app')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Post('upload-image')
  @ApiConsumes('multipart/form-data')
  @UseInterceptors(FileInterceptor('file'))
  async uploadImage(
    @Body() body: FileDto,
    @UploadedFile(
      ImageFileValidationPipe,
      new ParseFilePipeBuilder().build({
        fileIsRequired: true,
      }),
    )
    file: Express.Multer.File,
  ) {
    try {
      const fileUploaded = this.appService.updateImage(file);
      return fileUploaded;
    } catch (error) {
      throw error;
    }
  }
}

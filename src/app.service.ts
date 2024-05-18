import { Injectable } from '@nestjs/common';
import { CloudinaryService } from './cloudinary/cloudinary.service';

@Injectable()
export class AppService {
  constructor(private cloudinaryService: CloudinaryService) {}
  async updateImage(file: Express.Multer.File) {
    file.originalname = file.originalname.split(' ').join('_');
    const cloudFileResponse = await this.cloudinaryService.uploadImage(file);
    return cloudFileResponse;
  }
}

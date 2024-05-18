import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { ApiBearerAuth, ApiBody, ApiTags } from '@nestjs/swagger';
import { IUserRequest, UserRequest } from 'src/users/user.decorator';
import { CreateReportDto } from './dto/create-report.dto';

@Controller('posts')
@ApiTags('posts')
@ApiBearerAuth()
export class PostsController {
  constructor(private readonly postsService: PostsService) {}

  @Post()
  create(
    @Body() createPostDto: CreatePostDto,
    @UserRequest() user: IUserRequest,
  ) {
    return this.postsService.create(createPostDto, user);
  }

  @Get()
  findAll() {
    return this.postsService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.postsService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updatePostDto: UpdatePostDto) {
    return this.postsService.update(+id, updatePostDto);
  }

  @Post('report/:id')
  report(
    @Param('id') id: string,
    @UserRequest() user: IUserRequest,
    @Body() report: CreateReportDto,
  ) {
    return this.postsService.report(+id, report.reason, user);
  }

  @Post('read/:id')
  read(@Param('id') id: string, @UserRequest() user: IUserRequest) {
    return this.postsService.read(+id, user);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.postsService.remove(+id);
  }
}

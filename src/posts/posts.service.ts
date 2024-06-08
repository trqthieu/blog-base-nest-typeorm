import { BadRequestException, Injectable } from '@nestjs/common';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { CategoriesService } from 'src/categories/categories.service';
import { UsersService } from 'src/users/users.service';
import { IUserRequest } from 'src/users/user.decorator';
import { Post } from 'src/typeorm/Post.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { log } from 'console';
import { Report } from 'src/typeorm/Report.entity';

@Injectable()
export class PostsService {
  constructor(
    private readonly categoriesService: CategoriesService,
    private readonly usersService: UsersService,
    @InjectRepository(Post)
    private PostRepository: Repository<Post>,
    @InjectRepository(Report)
    private ReportRepository: Repository<Report>,
  ) {}
  async create(createPostDto: CreatePostDto, user: IUserRequest) {
    const { title, content, coverImage, categoryId } = createPostDto;
    const category = await this.categoriesService.findOne(categoryId);
    const userRequest = await this.usersService.findOne(user.id);
    if (!category) {
      throw new BadRequestException('Category not found');
    }
    const post = new Post();
    post.title = title;
    post.content = content;
    post.coverImage = coverImage;
    post.category = category;
    post.user = userRequest;
    return await this.PostRepository.save(post);
  }

  async findAll() {
    return await this.PostRepository.find({
      relations: {
        category: true,
        user: true,
      },
    });
  }

  async findOne(id: number) {
    return await this.PostRepository.findOne({
      where: { id },
      relations: {
        category: true,
        user: true,
      },
    });
  }

  async update(id: number, updatePostDto: UpdatePostDto) {
    const { categoryId, content, coverImage, title } = updatePostDto;
    const post = await this.findOne(id);
    if (!post) {
      throw new BadRequestException('Post not found');
    }
    if (title) {
      post.title = title;
    }
    if (coverImage) {
      post.coverImage = coverImage;
    }
    if (content) {
      post.content = content;
    }
    if (categoryId) {
      const category = await this.categoriesService.findOne(categoryId);
      if (!category) {
        throw new BadRequestException('Category not found');
      }
      post.category = category;
    }
    return await this.PostRepository.save(post);
  }

  async report(id: number, reason: string, user: IUserRequest) {
    const post = await this.findOne(id);
    if (!post) {
      throw new BadRequestException('Post not found');
    }
    const userRequest = await this.usersService.findOne(user.id);
    const existedReport = await this.ReportRepository.findOne({
      where: {
        post: {
          id: post.id,
        },
        user: {
          id: userRequest.id,
        },
      },
    });
    if (existedReport) {
      throw new BadRequestException('Report has been existed');
    }
    const report = new Report();
    report.post = post;
    report.user = userRequest;
    report.reason = reason;
    return await this.ReportRepository.save(report);
  }

  async read(id: number, user: IUserRequest) {
    const post = await this.findOne(id);
    if (!post) {
      throw new BadRequestException('Post not found');
    }
    const userRequest = await this.usersService.findOne(user.id);
    post.readCount = post.readCount + 1;
    return await this.PostRepository.save(post);
  }

  async remove(id: number) {
    const post = await this.findOne(id);
    if (!post) {
      throw new BadRequestException('Post not found');
    }
    return await this.PostRepository.remove(post);
  }
}

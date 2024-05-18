import { Module } from '@nestjs/common';
import { PostsService } from './posts.service';
import { PostsController } from './posts.controller';
import { CategoriesModule } from 'src/categories/categories.module';
import { UsersModule } from 'src/users/users.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Post } from 'src/typeorm/Post.entity';
import { Report } from 'src/typeorm/Report.entity';

@Module({
  imports: [
    CategoriesModule,
    UsersModule,
    TypeOrmModule.forFeature([Post, Report]),
  ],
  controllers: [PostsController],
  providers: [PostsService],
})
export class PostsModule {}

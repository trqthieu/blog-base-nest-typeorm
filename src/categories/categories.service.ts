import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateCategoryDto } from './dto/create-category.dto';
import { UpdateCategoryDto } from './dto/update-category.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/typeorm/User.entity';
import { Repository } from 'typeorm';
import { Category } from 'src/typeorm/Category.entity';

@Injectable()
export class CategoriesService {
  constructor(
    @InjectRepository(Category)
    private categoryRepository: Repository<Category>,
  ) {}
  async create(createCategoryDto: CreateCategoryDto) {
    const existedCategory = await this.categoryRepository.findOne({
      where: {
        name: createCategoryDto.name,
      },
    });
    if (existedCategory) {
      throw new BadRequestException('Category name is duplicate');
    }
    const category = new Category();
    category.name = createCategoryDto.name;
    category.image = createCategoryDto.image;
    return await this.categoryRepository.save(category);
  }

  async findAll() {
    return await this.categoryRepository.find({});
  }

  async findOne(id: number) {
    return await this.categoryRepository.findOne({
      where: {
        id,
      },
    });
  }

  async update(id: number, updateCategoryDto: UpdateCategoryDto) {
    const category = await this.findOne(id);
    if (!category) {
      throw new BadRequestException('Category not found');
    }
    const { name, image } = updateCategoryDto;
    if (name) {
      category.name = name;
    }
    if (image) {
      category.image = image;
    }
    return await this.categoryRepository.save(category);
  }

  async remove(id: number) {
    const category = await this.findOne(id);
    if (!category) {
      throw new BadRequestException('Category not found');
    }
    return await this.categoryRepository.remove(category);
  }
}

/* eslint-disable prettier/prettier */
import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Category } from './Category.entity';
import { User } from './User.entity';
import { Report } from './Report.entity';
@Entity()
export class Post {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    nullable: false,
  })
  title: string;

  @Column({
    nullable: true,
  })
  coverImage: string;

  @ManyToOne(() => Category, (category) => category.posts)
  category: Category;

  @ManyToOne(() => User, (user) => user.posts)
  user: User;

  @OneToMany(() => Report, (report) => report.post)
  reports: Report[];

  @Column({
    nullable: true,
    type: 'longtext',
  })
  content: string;

  @Column({
    nullable: true,
    default: 0,
  })
  readCount: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}

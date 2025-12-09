import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument, UserRole } from './user.schema';
import { Model } from 'mongoose';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
  ) {}

  createUser(lookupId: string, role: UserRole) {
    return this.userModel.create({
      lookup_id: lookupId,
      role,
    });
  }

  findByLookupId(lookup_id: string) {
    return this.userModel.findOne({ lookup_id });
  }

  findById(userId: string) {
    return this.userModel.findById(userId);
  }
}

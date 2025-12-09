import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Session } from './session.schema';

@Injectable()
export class SessionsService {
  constructor(
    @InjectModel(Session.name)
    private readonly sessionModel: Model<Session>,
  ) {}

  async createSession(data: any) {
    return this.sessionModel.create(data);
  }

  async findByRefreshToken(token: string) {
    return this.sessionModel.findOne({
      refresh_token: token,
      is_logged_out: false,
    });
  }

  async logoutSession(sessionId: string) {
    return this.sessionModel.updateOne(
      { _id: sessionId },
      { is_logged_out: true },
    );
  }
}

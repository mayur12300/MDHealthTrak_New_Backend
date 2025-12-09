import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import * as mongoose from 'mongoose';
import { User, UserSchema } from './user.schema';

@Schema({ timestamps: true })
export class Otp extends Document {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user_id: User;

  @Prop()
  mobile: string;

  @Prop()
  email: string;

  @Prop()
  otp: string;

  @Prop({ type: Date, required: true })
  otp_expiry: Date;

  @Prop()
  purpose: string; // signup, login, reset-password

  @Prop({
    required: false,
    match: /^\+\d{1,4}$/, // +1 , +91 , +971 etc.
  })
  country_code: string;

  @Prop({ default: false })
  is_verified: boolean;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);

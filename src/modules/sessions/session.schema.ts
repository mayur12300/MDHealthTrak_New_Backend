import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class Session extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  user_id: Types.ObjectId;

  // Store ONLY hashed refresh token
  @Prop({ required: true })
  refresh_token: string;

  // Optional (logging / debugging only)
  @Prop({ required: false })
  access_token?: string;

  @Prop({ default: false })
  is_logged_out: boolean;

  @Prop()
  device?: string;

  @Prop()
  ip_address?: string;

  @Prop()
  user_agent?: string;
}

export const SessionSchema = SchemaFactory.createForClass(Session);

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class Otp extends Document {
  @Prop({ type: Types.ObjectId, required: true })
  user_id: Types.ObjectId; // patient / doctor / family _id

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

// @Schema({ timestamps: true })
// export class Otp {
//   @Prop({ type: Types.ObjectId, required: true })
//   user_id: Types.ObjectId; // patient / doctor / family _id

//   @Prop()
//   mobile?: string;

//   @Prop()
//   email?: string;

//   @Prop()
//   country_code?: string;

//   @Prop({ required: true })
//   otp: string;

//   @Prop({ required: true })
//   otp_expiry: Date;

//   @Prop({ default: false })
//   is_used: boolean;
// }

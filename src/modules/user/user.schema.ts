import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type UserDocument = User & Document;

export enum UserRole {
  PATIENT = 'patient',
  DOCTOR = 'doctor',
  FAMILY = 'family',
}

@Schema({ timestamps: true })
export class User {
  //Reference to patient / doctor / family collection _id
  @Prop({
    type: Types.ObjectId,
    required: true,
    unique: true,
  })
  lookup_id: string; // UUID

  //User role
  @Prop({
    type: String,
    enum: Object.values(UserRole),
    required: true,
  })
  role: UserRole;

  // Account status
  @Prop({ default: true })
  is_active: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);

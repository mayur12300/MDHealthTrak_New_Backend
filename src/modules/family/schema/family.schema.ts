import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import * as mongoosePaginate from 'mongoose-paginate-v2';

export type FamilyDocument = Family & Document;

@Schema({
  timestamps: { createdAt: 'p_created', updatedAt: false },
})
export class Family {
  @Prop() uniqueId: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    index: true,
  })
  lookup_id: string;

  @Prop() firstname: string;
  @Prop() lastname: string;
  @Prop() middlename: string;
  @Prop() name: string;

  @Prop({ default: '' }) email: string;
  @Prop() mobile: string;
  @Prop() password: string;

  @Prop() address: string;
  @Prop() address_1: string;
  @Prop() address_2: string;
  @Prop() address_3: string;

  @Prop() image: string;
  @Prop() gender: string;

  @Prop({ type: Date, default: Date.now })
  date: Date;

  @Prop({ type: [Object] })
  myDoctors: any[];

  @Prop() hash: string;

  @Prop({ type: [Object] })
  sentRequest: any[];

  @Prop({ default: 0 })
  loginCount: number;

  @Prop({ default: 0 })
  active: number;

  @Prop({ default: 0 })
  status: number;

  @Prop({ default: 0 })
  archived: number;

  @Prop({ type: [Object] })
  notifications: any[];

  @Prop({ default: '' })
  device_token: string;

  @Prop({ default: '' })
  device_type: string;

  @Prop({ type: [Object] })
  shareWith: any[];

  @Prop() dob: string;

  @Prop({ default: 0 })
  numasstr: string;

  @Prop({ type: [Object] })
  myImages: any[];

  @Prop({ type: [Object] })
  myAddedImages: any[];

  @Prop({ default: 0 })
  badge: number;

  @Prop() otp: string;
  @Prop() logincode: string;

  @Prop({ default: 0 })
  auth: number;

  @Prop({ default: '' })
  tmploc: string;

  @Prop() lat: string;
  @Prop() lon: string;

  @Prop() ccode: string;
  @Prop() cname: string;
  @Prop() fullno: string;

  @Prop() networkStatus: string;

  @Prop() srt_name: string;

  @Prop({ default: 0 })
  lockdown: number;

  @Prop() salt: string;
  @Prop() tz: string;

  @Prop() country: string;
  @Prop() state: string;

  @Prop() screenshot_count: number;

  @Prop({ minlength: 5, maxlength: 6 })
  zip_code: number;

  @Prop({ default: 1 })
  iam: number;

  @Prop() tempPassword: string;

  @Prop({ default: false })
  isTempPassword: boolean;

  @Prop({ default: 'family' })
  role: string;

  @Prop()
  googleId: string;

  @Prop()
  facebookId: string;

  @Prop()
  appleId: string;

  @Prop({
    type: [
      {
        patient_id: {
          type: Types.ObjectId,
          ref: 'patientModel',
        },
        status: {
          type: String,
          enum: ['requested', 'accepted', 'rejected'],
          default: 'accepted',
        },
        sentBy: {
          type: String,
          enum: ['family', 'patient'],
          default: 'patient',
        },
      },
    ],
  })
  conn_requests: any[];

  @Prop()
  userId: string;

  @Prop({
  type: {
    provider: {
      type: String,
      enum: ['google', 'facebook', 'apple'],
    },
    providerId: String,
    email: String,
    name: String,
    avatar: String,
    emailVerified: Boolean,
  },
})
socialAuth?: {
  provider?: 'google' | 'facebook' | 'apple';
  providerId?: string;
  email?: string;
  name?: string;
  avatar?: string;
  emailVerified?: boolean;
};

@Prop({ default: false })
isSocialLogin: boolean;

}

export const FamilySchema = SchemaFactory.createForClass(Family);

// Pagination plugin
FamilySchema.plugin(mongoosePaginate);

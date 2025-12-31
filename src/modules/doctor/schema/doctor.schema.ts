import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import * as mongoosePaginate from 'mongoose-paginate-v2';

export type DoctorDocument = Doctor & Document;

@Schema({
  timestamps: { createdAt: 'created', updatedAt: 'updated' },
})
export class Doctor {
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
  @Prop() postname: string;
  @Prop() name: string;

  @Prop() address: string;
  @Prop() address_1: string;
  @Prop() address_2: string;
  @Prop() address_3: string;

  @Prop({ minlength: 5, maxlength: 6 })
  zip_code: number;

  @Prop({ type: [Object] })
  practice_address: any[];

  @Prop() mobile: string;
  @Prop() fax: string;
  @Prop() altfax: string;
  @Prop() gender: string;
  @Prop() dob: string;

  @Prop() exp: string;
  @Prop() experience: string;

  @Prop() email: string;
  @Prop() password: string;

  @Prop({ type: Types.ObjectId, ref: 'facilityModel' })
  facility_id: Types.ObjectId;

  @Prop({ type: [Object] }) skills: any[];
  @Prop() image: string;
  @Prop({ type: [Object] }) document: any[];
  @Prop() school: string;
  @Prop() passingYear: number;

  @Prop({ type: [Object] }) speciality: any[];
  @Prop() NPI_group: number;

  @Prop({ type: [Object] }) diseases: any[];
  @Prop({ type: [Object] }) symptoms: any[];
  @Prop({ type: [Object] }) events: any[];
  @Prop({ type: [Object] }) notifications: any[];

  @Prop({ default: 0 }) loginCount: number;
  @Prop({ default: 0 }) isUpdate: number;
  @Prop({ default: 0 }) archived: number;
  @Prop({ default: 0 }) wallet: number;

  @Prop({ type: [Object] }) invoice: any[];

  @Prop() device_token: string;
  @Prop() device_type: string;

  @Prop({ type: [Object] }) shareWith: any[];

  @Prop({ default: 0 }) active: number;
  @Prop({ default: 0 }) status: number;

  @Prop({ default: 0 }) rating: number;
  @Prop({ default: 0 }) totalRating: number;
  @Prop({ default: 0 }) totalRatingCount: number;
  @Prop({ default: 0 }) percentage: number;

  @Prop({ default: 0 }) fee: number;
  @Prop({ default: '' }) skype_link: string;

  @Prop({ type: [Object], default: [] }) calendar: any[];
  @Prop({ type: [Object] }) bookedApts: any[];

  @Prop() timeslot: number;
  @Prop({ default: 0 }) badge: number;

  @Prop() doctorType: string;
  @Prop() otp: string;
  @Prop() logincode: string;

  @Prop() license: string;
  @Prop() npi: string;

  @Prop({ type: [Object] }) taxonomies: any[];
  @Prop({ type: [Object] }) tags: any[];
  @Prop({ type: [Object] }) addresses: any[];
  @Prop({ type: [Object] }) identifiers: any[];
  @Prop({ type: [Object] }) basic: any[];

  @Prop() enumeration_type: string;

  @Prop() ccode: string;
  @Prop() cname: string;
  @Prop() fullno: string;

  @Prop({ default: 1 }) auth: number;

  @Prop() lat: string;
  @Prop() lon: string;

  @Prop() video: boolean;
  @Prop() inperson: boolean;

  @Prop() amount: number;

  @Prop({ default: 0 }) video_admin_amount: number;
  @Prop({ default: 0 }) Inperson_admin_amount: number;
  @Prop({ default: 0 }) video_amount_u_receive: number;
  @Prop({ default: 0 }) Inperson_amount_u_receive: number;

  @Prop({ default: 0 }) video_amount: number;
  @Prop({ default: 0 }) inPerson_amount: number;

  @Prop({ default: 0 }) medical_verified: number;
  @Prop({ default: 0 }) lockdown: number;

  @Prop() tz: string;
  @Prop() country: string;
  @Prop() state: string;
  @Prop() city: string;

  @Prop() clinic_name: string;
  @Prop() street: string;

  @Prop({ type: [Object] }) education: any[];

  @Prop({ enum: ['video-consulting', 'in-person', 'both'] })
  consultation_type: string;

  @Prop()
  googleId: string;

  @Prop()
  facebookId: string;

  @Prop()
  appleId: string;

  @Prop({
    type: [
      {
        plan_id: Types.ObjectId,
        checked: Boolean,
        doctor_fee: Number,
        created_at: Date,
        name: String,
        duration: Number,
        description: String,
        commission_fee: Number,
        no_of_message: Number,
        days: Number,
        subscription_type: String,
        subscription_type_id: Types.ObjectId,
      },
    ],
  })
  sub_package: any[];

  @Prop({
    type: [
      {
        packageId: Types.ObjectId,
        days: Number,
        duration: Number,
        name: String,
        rate: Number,
        description: String,
      },
    ],
  })
  share_sub_package: any[];

  @Prop({
    type: {
      accountId: String,
      isVerified: { type: Boolean, default: false },
      bank: [Object],
    },
  })
  stripe: any;

  @Prop() sales: string;
  @Prop() website: string;
  @Prop() sic_code: string;
  @Prop() employees: string;

  @Prop({ default: 'doctor' }) role: string;
  @Prop() userId: string;

  @Prop() qualification: string;
  @Prop() verified_practitioner: boolean;
  @Prop() bio: string;

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

  /** Optional flag */
  @Prop({ default: false })
  isSocialLogin: boolean;
}

export const DoctorSchema = SchemaFactory.createForClass(Doctor);

// Pagination
DoctorSchema.plugin(mongoosePaginate);

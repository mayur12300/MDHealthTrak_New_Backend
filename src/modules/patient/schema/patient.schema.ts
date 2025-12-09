import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import * as mongoosePaginate from 'mongoose-paginate-v2';

@Schema({ timestamps: true })
export class Patient extends Document {
  @Prop() uniqueId?: string;

  @Prop({
    type: String,
    required: true,
    unique: true,
    index: true,
  })
  lookup_id: string; // SAME UUID

  @Prop() firstname?: string;
  @Prop() lastname?: string;
  @Prop() middlename?: string;
  @Prop() name?: string;

  @Prop({ default: '' }) email?: string;
  @Prop() mobile?: string;

  @Prop() password?: string;

  @Prop() address?: string;
  @Prop() address_1?: string;
  @Prop() address_2?: string;
  @Prop() address_3?: string;

  @Prop() image?: string;
  @Prop() gender?: string;

  @Prop({ default: Date.now }) date: Date;

  @Prop({ type: [Object], default: [] }) paymentHistory: any[];
  @Prop({ type: [Object], default: [] }) medicalHistory: any[];
  @Prop({ type: [Object], default: [] }) mySymptoms: any[];
  @Prop({ type: [Object], default: [] }) myDataRecordings: any[];

  @Prop({ type: [Object], default: [] }) acceptedSymptomsByDoctor: any[];
  @Prop({ type: [Object], default: [] }) rejectedSymptomsByDoctor: any[];
  @Prop({ type: [Object], default: [] }) familyMembers: any[];

  @Prop() planType?: number;
  @Prop({ type: [Object], default: [] }) myDoctors: any[];

  @Prop() hash?: string;
  @Prop({ type: [Object], default: [] }) sentRequest: any[];

  @Prop({ default: 0 }) loginCount: number;
  @Prop({ default: 0 }) active: number;
  @Prop({ default: 0 }) status: number;
  @Prop({ default: 0 }) archived: number;

  @Prop({ type: [Object], default: [] }) notifications: any[];

  @Prop({ default: '' }) device_token?: string;
  @Prop({ default: '' }) device_type?: string;
  @Prop({ type: [String], default: [] }) device_name: string[];

  @Prop({ type: [Object], default: [] }) shareWith: any[];

  @Prop({ default: 0 }) wallet: number;

  @Prop() bloodgroup?: string;
  @Prop() dob?: string;

  @Prop({ default: '0' }) numasstr?: string;

  @Prop({ type: [Object], default: [] }) myImages: any[];
  @Prop({ type: [Object], default: [] }) myAddedImages: any[];

  @Prop({ type: [Object], default: [] }) shareSymptomWith: any[];

  @Prop({ default: 0 }) badge: number;

  @Prop() otp?: string;
  @Prop() logincode?: string;

  @Prop({ default: 0 }) auth: number;

  @Prop({ default: '' }) tmploc?: string;
  @Prop() lat?: string;
  @Prop() lon?: string;
  @Prop() ccode?: string;
  @Prop() cname?: string;
  @Prop() fullno?: string;

  @Prop() networkStatus?: string;

  @Prop({ default: Date.now }) p_created: Date;
  @Prop() srt_name?: string;

  @Prop({ default: 0 }) lockdown: number;

  @Prop() salt?: string;
  @Prop() tz?: string;
  @Prop() country?: string;
  @Prop() state?: string;
  @Prop() speciality?: string;

  @Prop() screenshot_count?: number;

  @Prop({
    type: {
      active: Boolean,
      key: String,
      doctorId: String,
    },
  })
  created_by_doctor?: {
    active?: boolean;
    key?: string;
    doctorId?: string;
  };

  @Prop({
    type: {
      accountId: String,
      isVerified: { type: Boolean, default: false },
      card: { type: [Object], default: [] },
    },
  })
  card_info?: {
    accountId?: string;
    isVerified?: boolean;
    card?: any[];
  };

  @Prop({
    type: [
      {
        doctor_lookup_id: String,
        status: Boolean,
      },
    ],
    default: [],
  })
  consultant_doctor: {
    doctor_lookup_id: string;
    status: boolean;
  }[];

  @Prop({
    type: [
      {
        isVerified: { type: Boolean, default: false },
        card_number: String,
        expiry_date: String,
        cvv: String,
        postal_code: Number,
      },
    ],
    default: [],
  })
  cards: any[];

  @Prop() room_no?: string;
  @Prop() room_type?: string;

  @Prop() zip_code?: number;

  @Prop({ default: 1 }) iam: number;
  @Prop({ default: 'resident' }) role: string;

  @Prop() tempPassword?: string;
  @Prop({ default: false }) isTempPassword: boolean;

  @Prop() userId?: string;

  @Prop()
  googleId: string;

  @Prop()
  facebookId: string;

  @Prop()
  appleId: string;
}

export const PatientSchema = SchemaFactory.createForClass(Patient);

// Pagination plugin
PatientSchema.plugin(mongoosePaginate);

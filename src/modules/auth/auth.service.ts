import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User, UserSchema } from '../user/user.schema';
import { Otp, OtpSchema } from '../user/otp.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model, PaginateModel } from 'mongoose';
import {
  ForgotPasswordEmailDto,
  ForgotPasswordMobileDto,
  LoginDto,
  LoginVerifyOtpDto,
  ResetPasswordDto,
  SendOtpDto,
  UserRole,
} from './dto';
import { SessionsService } from '../sessions/sessions.service';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config/dist/config.service';
import { Family, FamilyDocument } from '../family/schema/family.schema';
import { Doctor, DoctorDocument } from '../doctor/schema/doctor.schema';
import { Patient } from '../patient/schema/patient.schema';
import type { StringValue } from 'ms';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,

    @InjectModel(Otp.name)
    private readonly otpModel: Model<Otp>,

    @InjectModel(User.name)
    private readonly userModel: Model<User>,

    @InjectModel(Family.name)
    private familyModel: PaginateModel<FamilyDocument>,

    @InjectModel(Doctor.name)
    private doctorModel: PaginateModel<DoctorDocument>,

    @InjectModel(Patient.name)
    private patientModel: PaginateModel<DoctorDocument>,

    private readonly sessionsService: SessionsService,
  ) {}

  // SEND OTP
  async sendOtp(dto: SendOtpDto) {
    const { mobile, email, country_code } = dto;

    if (!mobile && !email) {
      throw new BadRequestException('mobile or Email is required');
    }

    const orConditions: any[] = [];

    if (email) {
      orConditions.push({ email });
    }

    if (mobile) {
      orConditions.push({
        mobile,
        country_code: country_code || '+91',
      });
    }

    // Check if user exists
    const otpDoc = await this.otpModel.findOne({ $or: orConditions });

    if (otpDoc) {
      throw new BadRequestException('Mobile or email already registered');
    }

    const countryCode = country_code || '+91';
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('otp : ', otp);

    const query: any = { country_code: countryCode };
    if (mobile) query.mobile = mobile;
    if (email) query.email = email;

    let user = await this.otpModel.findOne(query);

    if (!user) {
      user = new this.otpModel(query);
    }

    user.otp = otp;
    user.otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    return {
      success: true,
      message: 'OTP sent successfully',
    };
  }

  async verifyOtp(
    mobile?: string,
    email?: string,
    otp?: string,
    country_code?: string,
  ) {
    if (!mobile && !email)
      throw new BadRequestException('Mobile or Email is required');
    if (!otp) throw new BadRequestException('OTP is required');

    const orConditions: any[] = [];

    if (email) {
      orConditions.push({ email });
    }

    if (mobile) {
      orConditions.push({
        mobile,
        country_code: country_code || '+91',
      });
    }

    if (!orConditions.length)
      throw new BadRequestException('Email or mobile is required');

    const otpDoc = await this.otpModel.findOne({ $or: orConditions });

    if (!otpDoc) throw new BadRequestException('OTP record not found');
    if (otpDoc.otp !== otp) throw new UnauthorizedException('Invalid OTP');
    if (otpDoc.otp_expiry < new Date())
      throw new UnauthorizedException('OTP expired');

    otpDoc.is_verified = true;
    // otpDoc.otp = null;
    await otpDoc.save();

    return { success: true, message: 'OTP verified successfully' };
  }

  async signup(
    role: UserRole,
    mobile?: string,
    email?: string,
    password?: string,
    confirm_password?: string,
    country_code?: string,
  ) {
    if (!mobile && !email) {
      throw new BadRequestException('Mobile or Email is required');
    }

    if (!password || !confirm_password) {
      throw new BadRequestException(
        'Password and confirm password are required',
      );
    }

    if (password !== confirm_password) {
      throw new BadRequestException('Passwords do not match');
    }

    /* OTP verification */
    const otpDoc = await this.otpModel.findOne({
      $or: [{ mobile }, { email }],
      is_verified: true,
    });

    if (!otpDoc) {
      throw new BadRequestException('OTP verification required');
    }

    /* Check existing role entity */
    let lookupEntity;

    const lookupId = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    switch (role) {
      case UserRole.PATIENT:
        lookupEntity = await this.patientModel.findOne({
          $or: [{ mobile }, { email }],
        });
        if (lookupEntity)
          throw new BadRequestException('Patient already exists');

        lookupEntity = await this.patientModel.create({
          lookup_id: lookupId,
          country_code,
          mobile,
          email,
          password: hashedPassword,
          is_verified: true,
        });
        break;

      case UserRole.DOCTOR:
        lookupEntity = await this.doctorModel.findOne({
          $or: [{ mobile }, { email }],
        });
        if (lookupEntity)
          throw new BadRequestException('Doctor already exists');

        lookupEntity = await this.doctorModel.create({
          lookup_id: lookupId,
          country_code,
          mobile,
          email,
          password: hashedPassword,
        });
        break;

      case UserRole.FAMILY:
        lookupEntity = await this.familyModel.findOne({
          $or: [{ mobile }, { email }],
        });
        if (lookupEntity)
          throw new BadRequestException('Family already exists');

        lookupEntity = await this.familyModel.create({
          lookup_id: lookupId,
          country_code,
          mobile,
          email,
          password: hashedPassword,
        });
        break;

      default:
        throw new BadRequestException('Invalid role');
    }

    //Create USER role mapping
    const user = await this.userModel.create({
      user_id: lookupEntity._id,
      lookup_id: lookupId,
      role,
    });

    return {
      success: true,
      message: 'Signup successful',
      data: {
        user_id: user._id,
        lookup_id: lookupId,
        role,
      },
    };
  }

  // Login
  async login(dto: LoginDto, req: Request) {
    const { email, mobile, password } = dto;

    if (!email && !mobile)
      throw new BadRequestException('Email or mobile is required');

    let account =
      (email &&
        ((await this.patientModel.findOne({ email })) ||
          (await this.doctorModel.findOne({ email })))) ||
      (mobile &&
        ((await this.patientModel.findOne({ mobile })) ||
          (await this.doctorModel.findOne({ mobile })) ||
          (await this.familyModel.findOne({ mobile }))));

    if (!account) throw new BadRequestException('User not found');

    if (!(await bcrypt.compare(password, account.password)))
      throw new BadRequestException('Incorrect password');

    const user = await this.userModel.findOne({ lookup_id: account.lookup_id });
    if (!user) throw new BadRequestException('User role mapping not found');

    const payload = { user_id: account._id.toString(), role: user.role };

    const accessExp: StringValue = (this.configService.get(
      'ACCESS_TOKEN_EXPIRES_IN',
    ) ?? '15m') as StringValue;

    const refreshExp: StringValue = (this.configService.get(
      'REFRESH_TOKEN_EXPIRES_IN',
    ) ?? '7d') as StringValue;

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: accessExp,
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: refreshExp,
    });

    const hashedaccess = await bcrypt.hash(accessToken, 10);

    const hashedRefresh = await bcrypt.hash(refreshToken, 10);

    const ipAddress =
      (req.headers['x-forwarded-for'] as string) ||
      req.socket.remoteAddress ||
      '0.0.0.0';

    const session = await this.sessionsService.createSession({
      user_id: user._id,
      access_token: hashedaccess,
      refresh_token: hashedRefresh,
      device: req.headers['user-agent'] || 'unknown',
      ip_address: ipAddress,
    });

    return {
      success: true,
      lookup_id: user.lookup_id,
      message: 'Login successful',
      user_id: user._id,
      role: user.role,
      access_token: accessToken,
      refresh_token: refreshToken,
      session_id: session._id,
    };
  }

  // SEND OTP
  async sendOtpMobile(dto: SendOtpDto) {
    const { mobile, email, country_code } = dto;

    if (!mobile) {
      throw new BadRequestException('mobile number is required');
    }

    const countryCode = country_code || '+91';
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('otp : ', otp);

    const query: any = { country_code: countryCode };
    if (mobile) query.mobile = mobile;
    if (email) query.email = email;

    let user = await this.otpModel.findOne(query);

    if (!user) {
      user = new this.otpModel(query);
    }

    user.otp = otp;
    user.otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    return {
      success: true,
      message: 'OTP sent successfully',
    };
  }

  async verifyOtpAndLogin(dto: LoginVerifyOtpDto, req: Request) {
    const { mobile, otp, country_code } = dto;

    if (!mobile) {
      throw new BadRequestException('Mobile or email is required');
    }

    if (!otp) {
      throw new BadRequestException('OTP is required');
    }

    const orConditions: any[] = [];

    if (mobile) {
      orConditions.push({
        mobile,
        country_code: country_code || '+91',
      });
    }

    const otpDoc = await this.otpModel.findOne({ $or: orConditions });

    if (!otpDoc) {
      throw new BadRequestException('OTP record not found');
    }

    if (otpDoc.otp !== otp) {
      throw new UnauthorizedException('Invalid OTP');
    }

    if (otpDoc.otp_expiry < new Date()) {
      throw new UnauthorizedException('OTP expired');
    }

    otpDoc.is_verified = true;
    // otpDoc.otp = null;
    await otpDoc.save();

    // Find account (patient / doctor / family)
    let account =
      mobile &&
      ((await this.patientModel.findOne({ mobile })) ||
        (await this.doctorModel.findOne({ mobile })) ||
        (await this.familyModel.findOne({ mobile })));

    if (!account) {
      throw new BadRequestException('User not found');
    }

    const user = await this.userModel.findOne({
      lookup_id: account.lookup_id,
    });

    if (!user) {
      throw new BadRequestException('User role mapping not found');
    }

    const payload = {
      user_id: account._id.toString(),
      role: user.role,
    };

    const accessExp: StringValue = (this.configService.get(
      'ACCESS_TOKEN_EXPIRES_IN',
    ) ?? '15m') as StringValue;

    const refreshExp: StringValue = (this.configService.get(
      'REFRESH_TOKEN_EXPIRES_IN',
    ) ?? '7d') as StringValue;

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: accessExp,
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: refreshExp,
    });

    const ipAddress =
      (req.headers['x-forwarded-for'] as string) ||
      req.socket.remoteAddress ||
      '0.0.0.0';

    const session = await this.sessionsService.createSession({
      user_id: user._id,
      access_token: await bcrypt.hash(accessToken, 10),
      refresh_token: await bcrypt.hash(refreshToken, 10),
      device: req.headers['user-agent'] || 'unknown',
      ip_address: ipAddress,
    });

    return {
      success: true,
      message: 'Login successful',
      user_id: user._id,
      lookup_id: user.lookup_id,
      role: user.role,
      access_token: accessToken,
      refresh_token: refreshToken,
      session_id: session._id,
    };
  }

  async logout(sessionId: string) {
    const session = await this.sessionsService.logoutSession(sessionId);

    if (!session) {
      throw new BadRequestException('Invalid session');
    }

    return {
      success: true,
      message: 'Logout successful',
    };
  }

  async signup_verify_otp(payload: any) {
    // TODO: Implement signup-verify-otp business logic
    return { success: true, api: 'signup-verify-otp', payload };
  }

  async signup_set_password(payload: any) {
    // TODO: Implement signup-set-password business logic
    return { success: true, api: 'signup-set-password', payload };
  }

  async signup_google(payload: any) {
    // TODO: Implement signup-google business logic
    return { success: true, api: 'signup-google', payload };
  }

  async signup_facebook(payload: any) {
    // TODO: Implement signup-facebook business logic
    return { success: true, api: 'signup-facebook', payload };
  }

  async signup_apple(payload: any) {
    // TODO: Implement signup-apple business logic
    return { success: true, api: 'signup-apple', payload };
  }

  async login_send_otp(payload: any) {
    // TODO: Implement login-send-otp business logic
    return { success: true, api: 'login-send-otp', payload };
  }

  async login_verify_otp(payload: any) {
    // TODO: Implement login-verify-otp business logic
    return { success: true, api: 'login-verify-otp', payload };
  }

  async login_email_password(payload: any) {
    // TODO: Implement login-email-password business logic
    return { success: true, api: 'login-email-password', payload };
  }

  async login_google(payload: any) {
    // TODO: Implement login-google business logic
    return { success: true, api: 'login-google', payload };
  }

  async login_facebook(payload: any) {
    // TODO: Implement login-facebook business logic
    return { success: true, api: 'login-facebook', payload };
  }

  async login_apple(payload: any) {
    // TODO: Implement login-apple business logic
    return { success: true, api: 'login-apple', payload };
  }

  async forgotPasswordMobile(dto: ForgotPasswordMobileDto) {
    const { mobile, country_code } = dto;

    const user =
      (await this.patientModel.findOne({ mobile })) ||
      (await this.doctorModel.findOne({ mobile })) ||
      (await this.familyModel.findOne({ mobile }));

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const mobileOtp = await this.otpModel.findOne({ mobile });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await this.otpModel.findOneAndUpdate(
      { user_id: mobileOtp._id },
      {
        mobile,
        country_code: country_code || '+91',
        otp,
        otp_expiry: new Date(Date.now() + 5 * 60 * 1000),
      },
      { upsert: true },
    );

    console.log(`Forgot password OTP sent to ${mobile}: ${otp}`);

    return {
      success: true,
      user_id: user._id,
      message: 'OTP sent to registered mobile number',
    };
  }

  async forgotPasswordEmail(dto: ForgotPasswordEmailDto) {
    const { email } = dto;

    const user =
      (await this.patientModel.findOne({ email })) ||
      (await this.doctorModel.findOne({ email })) ||
      (await this.familyModel.findOne({ email }));

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const emailOtp = await this.otpModel.findOne({ email });

    if (!emailOtp) {
      throw new BadRequestException('Email details not found');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await this.otpModel.findOneAndUpdate(
      { user_id: emailOtp._id },
      {
        email,
        otp,
        otp_expiry: new Date(Date.now() + 5 * 60 * 1000),
      },
      { upsert: true },
    );

    console.log(`Forgot password OTP sent to ${email}: ${otp}`);

    return {
      success: true,
      user_id: user._id,
      message: 'OTP sent to registered email',
    };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const { user_id, otp, password, confirm_password } = dto;

    if (password !== confirm_password) {
      throw new BadRequestException('Passwords do not match');
    }

    const otpDoc = await this.otpModel.findOne({
      otp,
      is_verified: false,
    });

    if (!otpDoc) {
      throw new BadRequestException('Invalid OTP');
    }

    if (otpDoc.otp_expiry < new Date()) {
      throw new BadRequestException('OTP expired');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const updated =
      (
        await this.patientModel.updateOne(
          { _id: user_id },
          { password: hashedPassword },
        )
      ).matchedCount ||
      (
        await this.doctorModel.updateOne(
          { _id: user_id },
          { password: hashedPassword },
        )
      ).matchedCount ||
      (
        await this.familyModel.updateOne(
          { _id: user_id },
          { password: hashedPassword },
        )
      ).matchedCount;

    if (!updated) {
      throw new BadRequestException('User not found');
    }

    otpDoc.is_verified = true;
    await otpDoc.save();

    return { success: true, message: 'Password reset successfully' };
  }
}

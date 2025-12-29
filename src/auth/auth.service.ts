import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User, UserSchema } from '../modules/user/user.schema';
import { Otp, OtpSchema } from '../modules/user/otp.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model, PaginateModel } from 'mongoose';
import {
  ForgotPasswordEmailDto,
  ForgotPasswordMobileDto,
  LoginDto,
  LoginVerifyOtpDto,
  ResetPasswordDto,
  SendOtpDto,
  SignupDto,
  UserRole,
} from './dto';
import { SessionsService } from '../modules/sessions/sessions.service';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config/dist/config.service';
import { Family, FamilyDocument } from '../modules/family/schema/family.schema';
import { Doctor, DoctorDocument } from '../modules/doctor/schema/doctor.schema';
import { Patient } from '../modules/patient/schema/patient.schema';
import type { StringValue } from 'ms';
import { v4 as uuidv4 } from 'uuid';
import { verifyFacebookToken, verifyGoogleToken } from 'src/config/socialmedia.config';

@Injectable()
export class AuthService {
  authService: any;
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
    throw new BadRequestException('Mobile or Email is required');
  }
 
  const countryCode = country_code || '+91';
 
  const query: any = { country_code: countryCode };
  if (mobile) query.mobile = mobile;
  if (email) query.email = email;
 
  // Generate OTP
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  console.log('OTP:', otp); // ⚠️ remove in production
 
  // Find existing OTP record
  let otpDoc = await this.otpModel.findOne(query);
 
    if (otpDoc) {
      throw new BadRequestException('Mobile or email already registered');
    }
  if (!otpDoc) {
    otpDoc = new this.otpModel(query);
  }
 
  // Reset OTP state
  otpDoc.otp = otp;
  otpDoc.is_verified = false;
  otpDoc.otp_expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 mins
 
  await otpDoc.save();
 
  return {
    success: true,
    message: 'OTP sent successfully',
  };
}


  // async sendOtp(dto: SendOtpDto) {
  //   const { mobile, email, country_code } = dto;

  //   if (!mobile && !email) {
  //     throw new BadRequestException('mobile or Email is required');
  //   }

  //   const orConditions: any[] = [];

  //   if (email) {
  //     orConditions.push({ email });
  //   }

  //   if (mobile) {
  //     orConditions.push({
  //       mobile,
  //       country_code: country_code || '+91',
  //     });
  //   }

  //   // Check if user exists
  //   const otpDoc = await this.otpModel.findOne({ $or: orConditions });

  //   // if (otpDoc) {
  //   //   throw new BadRequestException('Mobile or email already registered');
  //   // }

  //   const countryCode = country_code || '+91';
  //   const otp = Math.floor(1000 + Math.random() * 9000).toString();
  //   console.log('otp : ', otp);

  //   const query: any = { country_code: countryCode };
  //   if (mobile) query.mobile = mobile;
  //   if (email) query.email = email;

  //   let user = await this.otpModel.findOne(query);

  //   if (!user) {
  //     user = new this.otpModel(query);
  //   }

  //   user.otp = otp;
  //   user.otp_expiry = new Date(Date.now() + 5 * 60 * 1000);
  //   await user.save();

  //   return {
  //     success: true,
  //     message: 'OTP sent successfully',
  //   };
  // }

  // async verifyOtp(
  //   mobile?: string,
  //   email?: string,
  //   otp?: string,
  //   country_code?: string,
  // ) {
  //   if (!mobile && !email)
  //     throw new BadRequestException('Mobile or Email is required');
  //   if (!otp) throw new BadRequestException('OTP is required');

  //   const orConditions: any[] = [];

  //   if (email) {
  //     orConditions.push({ email });
  //   }

  //   if (mobile) {
  //     orConditions.push({
  //       mobile,
  //       country_code: country_code || '+91',
  //     });
  //   }

  //   if (!orConditions.length)
  //     throw new BadRequestException('Email or mobile is required');

  //   const otpDoc = await this.otpModel.findOne({ $or: orConditions,  is_verified: false});

  //   // if (!otpDoc) throw new BadRequestException('OTP record not found');
  //   if (otpDoc.otp !== otp) throw new UnauthorizedException('Invalid OTP');
  //   if (otpDoc.otp_expiry < new Date())
  //     throw new UnauthorizedException('OTP expired');

  //   otpDoc.is_verified = true;
  //   // otpDoc.otp = null;
  //   var data = await otpDoc.save();

  //   return { success: true, message: 'OTP verified successfully', isOtpVerified: data.is_verified, };
  // }

  async verifyOtp(
  mobile?: string,
  email?: string,
  otp?: string,
  country_code?: string,
) {
  if (!mobile && !email) {
    throw new BadRequestException('Mobile or Email is required');
  }

  if (!otp) {
    throw new BadRequestException('OTP is required');
  }

  const orConditions = [];

  if (email) {
    orConditions.push({ email });
  }

  if (mobile) {
    orConditions.push({
      mobile,
      country_code: country_code || '+91',
    });
  }

  const otpDoc = await this.otpModel.findOne({
    $or: orConditions,
    is_verified: false,
  });

  if (!otpDoc) {
    throw new BadRequestException('OTP not found or already verified');
  }

  if (otpDoc.otp !== otp) {
    throw new UnauthorizedException('Invalid OTP');
  }

  if (otpDoc.otp_expiry < new Date()) {
    throw new UnauthorizedException('OTP expired');
  }

  otpDoc.is_verified = true;
  // otpDoc.otp = null; // optional but recommended
  // otpDoc.otp_expiry = null;

  const data = await otpDoc.save();

  return {
    success: true,
    message: 'OTP verified successfully',
    isOtpVerified: data.is_verified,
  };
}


private async generateTokensAndSession(
  account: any,
  user: any,
  req: Request,
) {
  
  const payload = {
    user_id: account._id.toString(),
    role: user.role,
  };

  const accessExp = (this.configService.get(
    'ACCESS_TOKEN_EXPIRES_IN',
  ) ?? '15m') as StringValue;

  const refreshExp = (this.configService.get(
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

  const hashedAccess = await bcrypt.hash(accessToken, 10);
  const hashedRefresh = await bcrypt.hash(refreshToken, 10);

  const ipAddress =
    (req.headers['x-forwarded-for'] as string) ||
    req.socket.remoteAddress ||
    '0.0.0.0';

  const session = await this.sessionsService.createSession({
    user_id: user._id,
    access_token: hashedAccess,
    refresh_token: hashedRefresh,
    device: req.headers['user-agent'] || 'unknown',
    ip_address: ipAddress,
  });

  return {
    accessToken,
    refreshToken,
    sessionId: session._id,
  };
}

async signup(dto: SignupDto, req: Request) {
  const {
    role,
    mobile,
    email,
    password,
    confirm_password,
    country_code,
  } = dto;

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

  /* OTP verification (mandatory) */
  const otpDoc = await this.otpModel.findOne({
    $or: [
      email ? { email } : null,
      mobile ? { mobile, country_code: country_code || '+91' } : null,
    ].filter(Boolean),
    is_verified: true,
  });

  if (!otpDoc) {
    throw new BadRequestException('OTP verification required');
  }

  const lookupId = uuidv4();
  const hashedPassword = await bcrypt.hash(password, 10);

  let account: any;

  switch (role) {
    case UserRole.PATIENT:
      if (
        await this.patientModel.findOne({
          $or: [{ mobile }, { email }],
        })
      ) {
        throw new BadRequestException('Patient already exists');
      }

      account = await this.patientModel.create({
        lookup_id: lookupId,
        country_code: country_code || '+91',
        mobile,
        email,
        password: hashedPassword,
        is_verified: true,
      });
      break;

    case UserRole.DOCTOR:
      if (
        await this.doctorModel.findOne({
          $or: [{ mobile }, { email }],
        })
      ) {
        throw new BadRequestException('Doctor already exists');
      }

      account = await this.doctorModel.create({
        lookup_id: lookupId,
        country_code: country_code || '+91',
        mobile,
        email,
        password: hashedPassword,
      });
      break;

    case UserRole.FAMILY:
      if (
        await this.familyModel.findOne({
          $or: [{ mobile }, { email }],
        })
      ) {
        throw new BadRequestException('Family already exists');
      }

      account = await this.familyModel.create({
        lookup_id: lookupId,
        country_code: country_code || '+91',
        mobile,
        email,
        password: hashedPassword,
      });
      break;

    default:
      throw new BadRequestException('Invalid role');
  }

  /* Create USER role mapping */
  await this.userModel.create({
    user_id: account._id,
    lookup_id: lookupId,
    role,
  });

  /* Generate access + refresh token + session (same as login) */
  const { accessToken, refreshToken, sessionId } =
    await this.generateTokensAndSession(account, account, req);

  return {
    success: true,
    message: 'Signup successful',
    lookup_id: account.lookup_id,
    user_id: account._id,
    role: account.role,
    access_token: accessToken,
    refresh_token: refreshToken,
    session_id: sessionId,
  };
}


// async signup(dto: SignupDto, req: Request) {
//   const { email, mobile, password, role } = dto;

//   if (!email && !mobile) {
//     throw new BadRequestException('Email or mobile is required');
//   }

//   // Check if account already exists
//   const existingAccount =
//     (email &&
//       ((await this.patientModel.findOne({ email })) ||
//         (await this.doctorModel.findOne({ email })))) ||
//     (mobile &&
//       ((await this.patientModel.findOne({ mobile })) ||
//         (await this.doctorModel.findOne({ mobile })) ||
//         (await this.familyModel.findOne({ mobile }))));

//   if (existingAccount) {
//     throw new BadRequestException('User already registered');
//   }

//   const hashedPassword = await bcrypt.hash(password, 10);

//   // Create account (example: Patient)
//   const account = await this.patientModel.create({
//     lookup_id: existingAccount.lookup_id,
//     email,
//     mobile,
//     password: hashedPassword,
//   });

//   // Create user role mapping
//   await this.userModel.create({
//     lookup_id: account.lookup_id,
//     role,
//   });

//   // Generate tokens + session (same as login)
//   const { accessToken, refreshToken, sessionId } =
//     await this.generateTokensAndSession(account, existingAccount, req);

//   return {
//     success: true,
//     message: 'Signup successful',
//     lookup_id: existingAccount.lookup_id,
//     user_id: existingAccount._id,
//     role: existingAccount.role,
//     access_token: accessToken,
//     refresh_token: refreshToken,
//     session_id: sessionId,
//   };
// }


  // async signup(
  //   role: UserRole,
  //   mobile?: string,
  //   email?: string,
  //   password?: string,
  //   confirm_password?: string,
  //   country_code?: string,
  // ) {
  //   if (!mobile && !email) {
  //     throw new BadRequestException('Mobile or Email is required');
  //   }

  //   if (!password || !confirm_password) {
  //     throw new BadRequestException(
  //       'Password and confirm password are required',
  //     );
  //   }

  //   if (password !== confirm_password) {
  //     throw new BadRequestException('Passwords do not match');
  //   }

  //   /* OTP verification */
  //   const otpDoc = await this.otpModel.findOne({
  //     $or: [{ mobile }, { email }],
  //     is_verified: true,
  //   });

  //   if (!otpDoc) {
  //     throw new BadRequestException('OTP verification required');
  //   }

  //   /* Check existing role entity */
  //   let lookupEntity;

  //   const lookupId = uuidv4();
  //   const hashedPassword = await bcrypt.hash(password, 10);

  //   switch (role) {
  //     case UserRole.PATIENT:
  //       lookupEntity = await this.patientModel.findOne({
  //         $or: [{ mobile }, { email }],
  //       });
  //       if (lookupEntity)
  //         throw new BadRequestException('Patient already exists');

  //       lookupEntity = await this.patientModel.create({
  //         lookup_id: lookupId,
  //         country_code,
  //         mobile,
  //         email,
  //         password: hashedPassword,
  //         is_verified: true,
  //       });
  //       break;

  //     case UserRole.DOCTOR:
  //       lookupEntity = await this.doctorModel.findOne({
  //         $or: [{ mobile }, { email }],
  //       });
  //       if (lookupEntity)
  //         throw new BadRequestException('Doctor already exists');

  //       lookupEntity = await this.doctorModel.create({
  //         lookup_id: lookupId,
  //         country_code,
  //         mobile,
  //         email,
  //         password: hashedPassword,
  //       });
  //       break;

  //     case UserRole.FAMILY:
  //       lookupEntity = await this.familyModel.findOne({
  //         $or: [{ mobile }, { email }],
  //       });
  //       if (lookupEntity)
  //         throw new BadRequestException('Family already exists');

  //       lookupEntity = await this.familyModel.create({
  //         lookup_id: lookupId,
  //         country_code,
  //         mobile,
  //         email,
  //         password: hashedPassword,
  //       });
  //       break;

  //     default:
  //       throw new BadRequestException('Invalid role');
  //   }

  //   //Create USER role mapping
  //   await this.userModel.create({
  //     user_id: lookupEntity._id,
  //     lookup_id: lookupId,
  //     role,
  //   });

  //   return {
  //     success: true,
  //     message: 'Signup successful',
  //     data: {
  //       user_id: lookupEntity._id,
  //       lookup_id: lookupEntity.lookupId,
  //       role,
  //     },
  //   };
  // }

  // Login
  async login(dto: LoginDto, req: Request) {
    const { email, mobile, password } = dto;

    if (!email && !mobile)
      throw new BadRequestException('Email or mobile is required');

    let account =
      (email &&
        ((await this.patientModel.findOne({ email })) ||
        ((await this.patientModel.findOne({ email })) ||
          (await this.doctorModel.findOne({ email }))))) ||
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
 
    let account =
      (mobile &&
        ((await this.patientModel.findOne({ mobile })) ||
          (await this.doctorModel.findOne({ mobile })) ||
          (await this.familyModel.findOne({ mobile }))));
 
    if (!account) throw new BadRequestException('Mobile not found');
 
    const countryCode = country_code || '+91';
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
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

//  async signup_google(idToken: string, role: 'patient' | 'family' | 'doctor') {
//   const payload = await verifyGoogleToken(idToken);
//   console.log(payload, "verifyGoogleToken")

//   if (!payload?.email_verified) {
//     throw new UnauthorizedException('Google email not verified');
//   }

//   const { email, sub, name, picture } = payload;
//   const lookupId = uuidv4();

//   let model;

//   // Choose correct model
//   switch (role) {
//     case 'patient':
//       model = this.patientModel;
//       break;
//     case 'family':
//       model = this.familyModel;
//       break;
//     case 'doctor':
//       model = this.doctorModel;
//       break;
//     default:
//       throw new BadRequestException('Invalid role');
//   }

//   // Check existing user (any role)
//   let user =
//     (await this.patientModel.findOne({ email })) ||
//     (await this.familyModel.findOne({ email })) ||
//     (await this.doctorModel.findOne({ email }));

//   // Email already registered with different role
//   if (user && user.role !== role) {
//     throw new BadRequestException(
//       `Email already registered as ${user.role}`,
//     );
//   }

//   // Create user
//   if (!user) {
//     user = await model.create({
//       lookup_id: lookupId,
//       email,
//       name,
//       image: picture,
//       role,

//       // Unified social auth
//       socialAuth: {
//         provider: 'google',
//         providerId: sub,
//         email,
//         name,
//         avatar: picture,
//         emailVerified: payload.email_verified,
//       },

//       isSocialLogin: true,
//       active: 1,
//       status: 1,
//     });
//   }

//   // Generate tokens
//   const tokens = this.authService.generateTokens(user._id.toString());
//    await this.generateTokensAndSession(account, account, req);

//   console.log(tokens);

//   return {
//     message: 'Google signup successful',
//     user,
//     ...tokens,
//   };
// }


async signup_google(
  idToken: string,
  role: 'patient' | 'family' | 'doctor',
  req: Request,
) {
  const payload = await verifyGoogleToken(idToken);

  if (!payload?.email_verified) {
    throw new UnauthorizedException('Google email not verified');
  }

  const { email, sub, name, picture } = payload;
  const lookupId = uuidv4();

  let model;
  switch (role) {
    case 'patient':
      model = this.patientModel;
      break;
    case 'family':
      model = this.familyModel;
      break;
    case 'doctor':
      model = this.doctorModel;
      break;
    default:
      throw new BadRequestException('Invalid role');
  }

  // Check existing user across roles
  let user =
    (await this.patientModel.findOne({ email })) ||
    (await this.familyModel.findOne({ email })) ||
    (await this.doctorModel.findOne({ email }));

  if (user && user.role !== role) {
    throw new BadRequestException(
      `Email already registered as ${user.role}`,
    );
  }

  // Create user if not exists
  if (!user) {
    user = await model.create({
      lookup_id: lookupId,
      email,
      name,
      image: picture,
      role,
      socialAuth: {
        provider: 'google',
        providerId: sub,
        email,
        name,
        avatar: picture,
        emailVerified: payload.email_verified,
      },
      isSocialLogin: true,
      active: 1,
      status: 1,
    });
  }

  // SINGLE SOURCE OF TRUTH FOR TOKENS + SESSION
  const authData = await this.generateTokensAndSession(
    user, // account
    user, // user
    req,
  );

  return {
    message: 'Google signup successful',
    user,
    ...authData,
  };
}




async login_google(
  idToken: string,
  role: 'patient' | 'family' | 'doctor',
  req: Request,
) {
  const payload = await verifyGoogleToken(idToken);

  if (!payload?.email_verified) {
    throw new UnauthorizedException('Google email not verified');
  }

  const { email, sub, name, picture } = payload;

  let model;
  switch (role) {
    case 'patient':
      model = this.patientModel;
      break;
    case 'family':
      model = this.familyModel;
      break;
    case 'doctor':
      model = this.doctorModel;
      break;
    default:
      throw new BadRequestException('Invalid role');
  }

  // Find user
  const user = await model.findOne({
    $or: [
      { email },
      { 'socialAuth.providerId': sub },
      { googleId: sub }, // legacy
    ],
  });

  if (!user) {
    throw new NotFoundException(
      'Account not found. Please sign up first.',
    );
  }

  // Role validation
  if (user.role !== role) {
    throw new UnauthorizedException(
      `Account registered as ${user.role}`,
    );
  }

  // Sync social auth if missing
  if (!user.socialAuth?.providerId) {
    user.socialAuth = {
      provider: 'google',
      providerId: sub,
      email,
      name,
      avatar: picture,
      emailVerified: payload.email_verified,
    };
    user.isSocialLogin = true;
    await user.save();
  }

  // Update login metadata
  await model.updateOne(
    { _id: user._id },
    {
      $inc: { loginCount: 1 },
      $set: {
        device_token: null,
        device_type: null,
        lastLoginAt: new Date(),
      },
    },
  );

  // ✅ Tokens + Session (single source of truth)
  const authData = await this.generateTokensAndSession(
    user,
    user,
    req,
  );

  return {
    message: 'Google login successful',
    user,
    ...authData,
  };
}

// async login_google(
//   idToken: string,
//   role: 'patient' | 'family' | 'doctor',
// ) {
//   const payload = await verifyGoogleToken(idToken);

//   if (!payload?.email_verified) {
//     throw new UnauthorizedException('Google email not verified');
//   }

//   const { email, sub, name, picture } = payload;

//   let model;

//   switch (role) {
//     case 'patient':
//       model = this.patientModel;
//       break;
//     case 'family':
//       model = this.familyModel;
//       break;
//     case 'doctor':
//       model = this.doctorModel;
//       break;
//     default:
//       throw new BadRequestException('Invalid role');
//   }

//   // Find existing user
//   const user = await model.findOne({
//     $or: [
//       { email },
//       { 'socialAuth.providerId': sub },
//       { googleId: sub }, // legacy support
//     ],
//   });

//   if (!user) {
//     throw new NotFoundException(
//       'Account not found. Please sign up first.',
//     );
//   }

//   // Prevent wrong role login
//   if (user.role !== role) {
//     throw new UnauthorizedException(
//       `Account registered as ${user.role}`,
//     );
//   }

//   // Update social auth if missing
//   if (!user.socialAuth?.providerId) {
//     user.socialAuth = {
//       provider: 'google',
//       providerId: sub,
//       email,
//       name,
//       avatar: picture,
//       emailVerified: payload.email_verified,
//     };
//     user.isSocialLogin = true;
//     await user.save();
//   }

//   // Update login metadata
//   await model.updateOne(
//     { _id: user._id },
//     {
//       $inc: { loginCount: 1 },
//       $set: {
//         device_token: null,
//         device_type: null,
//       },
//     },
//   );

//   // Generate tokens
//   const tokens = this.authService.generateTokens(
//     user._id.toString(),
//   );

//   return {
//     message: 'Google login successful',
//     user,
//     ...tokens,
//   };
// }


  async signup_facebook(
  accessToken: string,
  role: 'patient' | 'family' | 'doctor',
  req: Request,
) {
  const payload = await verifyFacebookToken(accessToken);

  const { id, email, name, picture } = payload;
  const lookupId = uuidv4();

  let model;
  switch (role) {
    case 'patient':
      model = this.patientModel;
      break;
    case 'family':
      model = this.familyModel;
      break;
    case 'doctor':
      model = this.doctorModel;
      break;
    default:
      throw new BadRequestException('Invalid role');
  }

  // Check existing user across all roles
  let user =
    (await this.patientModel.findOne({ email })) ||
    (await this.familyModel.findOne({ email })) ||
    (await this.doctorModel.findOne({ email }));

  if (user) {
    throw new BadRequestException('Account already exists. Please login.');
  }

  user = await model.create({
    lookup_id: lookupId,
    email,
    name,
    image: picture,
    role,

    socialAuth: {
      provider: 'facebook',
      providerId: id,
      email,
      name,
      avatar: picture,
      emailVerified: true,
    },

    isSocialLogin: true,
    active: 1,
    status: 1,
  });

  // Create USER role mapping
  await this.userModel.create({
    user_id: user._id,
    lookup_id: lookupId,
    role,
  });

  const tokens = await this.generateTokensAndSession(
    user,
    user,
    req,
  );

  return {
    message: 'Facebook signup successful',
    user,
    ...tokens,
  };
}

async login_facebook(
  accessToken: string,
  role: 'patient' | 'family' | 'doctor',
  req: Request,
) {
  const payload = await verifyFacebookToken(accessToken);

  const { id, email, name, picture } = payload;

  let model;
  switch (role) {
    case 'patient':
      model = this.patientModel;
      break;
    case 'family':
      model = this.familyModel;
      break;
    case 'doctor':
      model = this.doctorModel;
      break;
    default:
      throw new BadRequestException('Invalid role');
  }

  const user = await model.findOne({
    $or: [
      { email },
      { 'socialAuth.providerId': id },
      { facebookId: id }, // legacy support
    ],
  });

  if (!user) {
    throw new NotFoundException(
      'Account not found. Please sign up first.',
    );
  }

  if (user.role !== role) {
    throw new UnauthorizedException(
      `Account registered as ${user.role}`,
    );
  }

  // Patch missing socialAuth
  if (!user.socialAuth?.providerId) {
    user.socialAuth = {
      provider: 'facebook',
      providerId: id,
      email,
      name,
      avatar: picture,
      emailVerified: true,
    };
    user.isSocialLogin = true;
    await user.save();
  }

  const tokens = await this.generateTokensAndSession(
    user,
    user,
    req,
  );

  return {
    message: 'Facebook login successful',
    user,
    ...tokens,
  };
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

  const otp = Math.floor(1000 + Math.random() * 9000).toString();

  await this.otpModel.findOneAndUpdate(
    { user_id: user._id },
    {
      user_id: user._id,
      mobile,
      country_code: country_code || '+91',
      otp,
      otp_expiry: new Date(Date.now() + 5 * 60 * 1000),
      is_verified: false,
    },
    { upsert: true, new: true },
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

  const otp = Math.floor(1000 + Math.random() * 9000).toString();

  await this.otpModel.findOneAndUpdate(
    { user_id: user._id }, // ✅ correct mapping
    {
      user_id: user._id,
      email,
      otp,
      otp_expiry: new Date(Date.now() + 5 * 60 * 1000),
      is_verified: false,
    },
    { upsert: true, new: true },
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

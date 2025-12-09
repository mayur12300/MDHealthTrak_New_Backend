import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User, UserSchema } from '../user/user.schema';
import { Otp, OtpSchema } from '../user/otp.schema';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { SessionsModule } from '../sessions/sessions.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Doctor, DoctorSchema } from '../doctor/schema/doctor.schema';
import { Patient, PatientSchema } from '../patient/schema/patient.schema';
import { Family, FamilySchema } from '../family/schema/family.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Otp.name, schema: OtpSchema },
      { name: Doctor.name, schema: DoctorSchema },
      { name: Patient.name, schema: PatientSchema },
      { name: Family.name, schema: FamilySchema },
    ]),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService): JwtModuleOptions => {
        const secret = configService.get<string>('auth.jwtSecret');
        const accessTokenExpiresIn = (configService.get<string>(
          'auth.accessTokenExpiresIn',
        ) ||
          '10m') as unknown as import('jsonwebtoken').SignOptions['expiresIn'];

        return {
          secret,
          signOptions: {
            expiresIn: accessTokenExpiresIn,
          },
        };
      },
    }),

    SessionsModule,
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}

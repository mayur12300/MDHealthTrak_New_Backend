// import { IsString, IsEmail, IsNotEmpty, Matches } from 'class-validator';

// export class SignupDto {
//   @IsString()
//   @IsNotEmpty()
//   mobile: string;

//   @IsEmail()
//   @IsNotEmpty()
//   email: string;

//   @IsString()
//   @IsNotEmpty()
//   @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/, {
//     message:
//       'Password must include uppercase, lowercase, number, special character',
//   })
//   password: string;

//   @IsString()
//   @IsNotEmpty()
//   confirm_password: string;
// }

import {
  IsEnum,
  IsOptional,
  IsString,
  IsEmail,
  IsNotEmpty,
  Matches,
} from 'class-validator';

export enum UserRole {
  PATIENT = 'patient',
  DOCTOR = 'doctor',
  FAMILY = 'family',
}

export class SignupDto {
  @IsEnum(UserRole)
  @IsNotEmpty()
  role: UserRole;

  @IsOptional()
  @IsString()
  mobile?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsString()
  @IsNotEmpty()
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/, {
    message:
      'Password must include uppercase, lowercase, number, special character',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  confirm_password: string;
  
@IsString()
  @IsNotEmpty()
  country_code: string;
}
